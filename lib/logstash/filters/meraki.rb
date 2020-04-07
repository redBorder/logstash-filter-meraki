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
  end

  public
  def filter(event)
    toDruid = {}
    toCache = {}

    clientMac = event.get(CLIENT_MAC)
    enrichment = event.get("enrichment")

    namespace_id = event.get(NAMESPACE_UUID) ? event.get(NAMESPACE_UUID) : ""

    timestamp = event.get(TIMESTAMP)

    if clientMac then
      toDruid[CLIENT_MAC] =  clientMac
      @dim_to_druid.each { |dimension| toDruid[dimension] = event.get(dimension) if event.get(dimension) }
      
      toCache.merge!(enrichment) if enrichment
      
      rssi = event.get(CLIENT_RSSI_NUM).to_i

      if event.include?(SRC)
        toCache[DOT11STATUS] = "ASSOCIATED"
      else
        toCache[DOT11STATUS] = "PROBING"
      end

     if rssi
       if rssi == 0
         rssiName = "unknown"
       elsif rssi <= (-85)
         rssiName = "bad"
       elsif rssi <= (-80)
         rssiName = "low"
       elsif rssi <= (-70)
         rssiName = "medium"
       elsif rssi <= (-60)
         rssiName = "good"
       else
         # No seria "excellent"??  
         rssiName = "excelent"
       end
       toCache[CLIENT_RSSI] = rssiName

       if rssi == 0
         toCache[CLIENT_PROFILE] = "hard"
       elsif rssi <= (-75)
         toCache[CLIENT_PROFILE] = "soft"
       elsif rssi <= (-65)
         toCache[CLIENT_PROFILE] = "medium"
       else
         toCache[CLIENT_PROFILE] = "hard"
       end
     end
     
     @store[clientMac] = toCache
     @memcached.set(LOCATION_STORE, @store)
     toDruid.merge!(toCache)

     store_enrichment = @store_manager.enrich(toDruid)
     store_enrichment.merge!(toDruid)

     namespace = store_enrichment[NAMESPACE_UUID]
     datasource = (namespace) ? DATASOURCE + "_" + namespace : DATASOURCE

     counterStore = @memcached.get(COUNTER_STORE)
     counterStore = Hash.new if counterStore.nil?
     counterStore[datasource] = counterStore[datasource].nil? ? 0 : (counterStore[datasource] + 1)
     @memcached.set(COUNTER_STORE,counterStore)


      flowsNumber = @memcached.get(FLOWS_NUMBER)
      flowsNumber = Hash.new if flowsNumber.nil?
      store_enrichment["flows_count"] = flowsNumber[datasource] if flowsNumber[datasource]  
      
      enrichmentEvent = LogStash::Event.new
      store_enrichment.each {|k,v| enrichmentEvent.set(k,v)}

      yield enrichmentEvent

    else
      @logger.warn("This event #{event} doesn't have client mac.")
    end #if else
    event.cancel
  end   # def filter
end     # class Logstash::Filter::Meraki
