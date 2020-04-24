# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "time"
require "dalli"
require "yaml"

require_relative "util/location_constant"
require_relative "util/memcached_config"
require_relative "store/store_manager"



class LogStash::Filters::Meraki < LogStash::Filters::Base
  include LocationConstant

  config_name "meraki"

  config :memcached_server, :validate => :string, :default => "", :required => false

  #Custom constants
  DATASOURCE =  "rb_location"
  
  public
  def register
    @dim_to_druid = [CLIENT_LATLNG, WIRELESS_STATION, CLIENT_MAC_VENDOR, CLIENT_RSSI_NUM, CLIENT_OS ]  
    
    @memcached_server = MemcachedConfig::servers.first if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0})
    @store = @memcached.get(LOCATION_STORE) || {}
    @store_manager = StoreManager.new(@memcached)  
    @last_refresh_stores = nil
  end

  public

  def refresh_stores
     return nil unless @last_refresh_stores.nil? || ((Time.now - @last_refresh_stores) > (60 * 5))
     @last_refresh_stores = Time.now
     e = LogStash::Event.new
     e.set("refresh_stores",true)
     return e
  end

  def filter(event)
    to_druid = {}
    to_cache = {}

    client_mac = event.get(CLIENT_MAC)
    enrichment = event.get("enrichment")

    namespace_id = event.get(NAMESPACE_UUID) ? event.get(NAMESPACE_UUID) : ""

    timestamp = event.get(TIMESTAMP)

    if client_mac then
      to_druid[CLIENT_MAC] =  client_mac
      @dim_to_druid.each { |dimension| to_druid[dimension] = event.get(dimension) if event.get(dimension) }
      
      to_cache.merge!(enrichment) if enrichment
      
      rssi = event.get(CLIENT_RSSI_NUM).to_i

      if event.include?(SRC)
        to_cache[DOT11STATUS] = "ASSOCIATED"
      else
        to_cache[DOT11STATUS] = "PROBING"
      end

     if rssi
       if rssi == 0
         rssi_name = "unknown"
       elsif rssi <= (-85)
         rssi_name = "bad"
       elsif rssi <= (-80)
         rssi_name = "low"
       elsif rssi <= (-70)
         rssi_name = "medium"
       elsif rssi <= (-60)
         rssi_name = "good"
       else
         rssi_name = "excellent"
       end
       to_cache[CLIENT_RSSI] = rssi_name

       if rssi == 0
         to_cache[CLIENT_PROFILE] = "hard"
       elsif rssi <= (-75)
         to_cache[CLIENT_PROFILE] = "soft"
       elsif rssi <= (-65)
         to_cache[CLIENT_PROFILE] = "medium"
       else
         to_cache[CLIENT_PROFILE] = "hard"
       end
     end
     
     @store[client_mac] = to_cache
     @memcached.set(LOCATION_STORE, @store)
     to_druid.merge!(to_cache)

     store_enrichment = @store_manager.enrich(to_druid)
     store_enrichment.merge!(to_druid)

     datasource = DATASOURCE
     namespace = store_enrichment[NAMESPACE_UUID]
     datasource = (namespace) ? DATASOURCE + "_" + namespace : DATASOURCE if (namespace && !namespace.empty?)

     counter_store = @memcached.get(COUNTER_STORE)
     counter_store = Hash.new if counter_store.nil?
     counter_store[datasource] = counter_store[datasource].nil? ? 0 : (counter_store[datasource] + 1)
     @memcached.set(COUNTER_STORE,counter_store)


      flows_number = @memcached.get(FLOWS_NUMBER)
      flows_number = Hash.new if flows_number.nil?
      store_enrichment["flows_count"] = flows_number[datasource] if flows_number[datasource]  
      
      enrichment_event = LogStash::Event.new
      store_enrichment.each {|k,v| enrichment_event.set(k,v)}

      yield enrichment_event

    else
      @logger.warn("This event #{event} doesn't have client mac.")
    end #if else

    event_refresh = refresh_stores
    yield event_refresh if event_refresh
    event.cancel
  end   # def filter
end     # class Logstash::Filter::Meraki
