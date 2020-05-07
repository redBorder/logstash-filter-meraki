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
  config :counter_store_counter, :validate => :boolean, :default => false,   :required => false
  config :flow_counter,          :validate => :boolean, :default => false,   :required => false
  config :update_stores_rate,    :validate => :number,  :default => 60,      :required => false

  #Custom constants
  DATASOURCE =  "rb_location"
  
  public
  def register
    @dim_to_cache = [CLIENT_LATLNG, WIRELESS_STATION, CLIENT_MAC_VENDOR, CLIENT_RSSI_NUM, CLIENT_OS ]  
    
    @memcached_server = MemcachedConfig::servers if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0})
    @store = @memcached.get(LOCATION_STORE) || {}
    @store_manager = StoreManager.new(@memcached, @update_stores_rate)  
  end

  public

  def filter(event)
    message = event.to_hash

    to_druid = {}
    to_cache = {}

    client_mac = message[CLIENT_MAC]

    if client_mac then
      @store = @memcached.get(LOCATION_STORE) || {}
      namespace_id = message[NAMESPACE_UUID] ? message[NAMESPACE_UUID] : ""
      timestamp = message[TIMESTAMP]

      to_cache = {} 
      @dim_to_cache.each { |dimension| to_cache[dimension] = message[dimension] if message[dimension] }
      to_druid = {}

      rssi = message[CLIENT_RSSI_NUM].to_i
      to_cache.merge!(message)

      if message[SRC]
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
     
      #@store[client_mac] = to_cache
      @store[client_mac + namespace_id] = to_cache
      @memcached.set(LOCATION_STORE, @store)

      to_druid.merge!(to_cache)

      store_enrichment = @store_manager.enrich(to_druid)
      store_enrichment.merge!(to_druid)

      if @counter_store_counter or @flow_counter
         datasource = store_enrichment[NAMESPACE_UUID] ? DATASOURCE + "_" + store_enrichment[NAMESPACE_UUID] :       DATASOURCE
 
         if @counter_store_counter
          counter_store = @memcached.get(COUNTER_STORE) || {}
          counter = counter_store[datasource] || 0
          counter_store[datasource] = counter + splitted_msg.size
          @memcached.set(COUNTER_STORE,counter_store)
         end
 
         if @flow_counter
          flows_number = @memcached.get(FLOWS_NUMBER) || {}
          store_enrichment["flows_count"] = (flows_number[datasource] || 0)
         end
      end
 
      enrichment_event = LogStash::Event.new
      store_enrichment.each {|k,v| enrichment_event.set(k,v)}

      yield enrichment_event

    else
      @logger.warn("This event #{event} doesn't have client mac.")
    end #if else

    event.cancel
  end   # def filter
end     # class Logstash::Filter::Meraki
