;;;
;;;   Copyright 2014, Frankfurt University of Applied Sciences
;;;
;;;   This software is released under the terms of the Eclipse Public License 
;;;   (EPL) 1.0. You can find a copy of the EPL at: 
;;;   http://opensource.org/licenses/eclipse-1.0.php
;;;

(ns
  ^{:author "Ruediger Gad",
    :doc "Utility functions."}
  drepcap.merger.util
  (:use clj-assorted-utils.util
        clojure.pprint
        [clojure.string :only (join)])
  (:require (clj-jms-activemq-toolkit [jms :as activemq]))
  (:import (clj_jms_activemq_toolkit ByteArrayWrapper)
           (clj_net_pcap ByteArrayHelper Counter PacketHeaderDataBean PcapByteArrayTimeStampComparator ProcessingLoop)
           (drepcap.merger ConsumeHelper)
           (java.util ArrayList Arrays HashMap)
           (java.util.concurrent BlockingQueue PriorityBlockingQueue)
           (java.nio ByteBuffer)))

(def ^:dynamic *queue-size* 100000)
(def ^:dynamic *send-limit* 10000)

(defn create-consume-fn [^Counter push-cntr ^Counter drop-cntr ^BlockingQueue merge-queue]
  (fn [^bytes b-array]
    (ConsumeHelper/consumeData b-array merge-queue, *queue-size*, push-cntr, drop-cntr)))

(defn add-sensor [sensor-id url merge-queue sensors input-compression]
  (let [push-cntr (Counter.)
        drop-cntr (Counter.)
        consume-fn (create-consume-fn push-cntr drop-cntr merge-queue)
        consumer (condp = input-compression
                   "lzf" (activemq/create-lzf-consumer url (str "/topic/pcap.single.raw." sensor-id ".data") consume-fn)
                   "snappy" (activemq/create-snappy-consumer url (str "/topic/pcap.single.raw." sensor-id ".data") consume-fn)
                   (activemq/create-consumer url (str "/topic/pcap.single.raw." sensor-id ".data") consume-fn))]
    (dosync
      (alter sensors assoc sensor-id {:push-counter push-cntr :drop-counter drop-cntr :consumer consumer}))))

(defn create-stats-fn [sensors delta-cntr monitor-producer ^Counter sent-counter silent]
  (let [time-tmp (atom (System/currentTimeMillis))]
    #(try
       (let [time-delta (- (System/currentTimeMillis) @time-tmp)
             _ (dosync (swap! time-tmp (fn [_] (System/currentTimeMillis))))
             individual-tmp (ref {})
             sum-eps (ref 0.0)
             sum-cnt (ref 0)]
         (doseq [sensor-id (sort (keys @sensors))]
           (let [cntr-val (.value ^Counter (get-in @sensors [sensor-id :push-counter]))
                 delta (delta-cntr (keyword sensor-id) cntr-val)
                 eps (float (/ delta (/ time-delta 1000.0)))]
             (dosync
               (alter individual-tmp assoc sensor-id {"eps" eps "total" cntr-val})
               (alter sum-eps + eps)
               (alter sum-cnt + cntr-val))))
         (let [sent-value (.value sent-counter)
               stats-map {"sent" {"eps" (delta-cntr :sent sent-value) "total" sent-value}
                          "sum" {"eps" @sum-eps "total" @sum-cnt}
                          "individual" @individual-tmp}]
           (monitor-producer (str stats-map))
           (when-not @silent
             (println stats-map))))
       (catch Exception e
         (.printStackTrace e)))))

