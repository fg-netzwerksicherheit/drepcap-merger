;;;
;;;   Copyright 2014, Frankfurt University of Applied Sciences
;;;
;;;   This software is released under the terms of the Eclipse Public License 
;;;   (EPL) 1.0. You can find a copy of the EPL at: 
;;;   http://opensource.org/licenses/eclipse-1.0.php
;;;

(ns
  ^{:author "Ruediger Gad",
    :doc "Main class"}
  drepcap.merger.main
  (:use clj-assorted-utils.util
        clojure.pprint
        clojure.tools.cli
        drepcap.merger.util)
  (:require (clj-jms-activemq-toolkit [jms :as activemq]))
  (:import (clj_jms_activemq_toolkit BytesMessagePayloadPart PooledBytesMessageProducer PooledBytesMessageProducer$CompressionMethod)
           (clj_net_pcap ByteArrayHelper Counter PacketHeaderDataBean PcapByteArrayTimeStampComparator ProcessingLoop)
           (drepcap.merger SendHelper)
           (java.io FileOutputStream)
           (java.nio ByteBuffer)
           (java.util ArrayList Arrays HashMap)
           (java.util.concurrent ArrayBlockingQueue BlockingQueue LinkedBlockingQueue PriorityBlockingQueue))
  (:gen-class))

(defn -main [& args]
  (let [cli-args (cli args
                      ["-d" "--duration"
                       "The duration in seconds how long the application is run."
                       :default -1
                       :parse-fn #(Integer. ^String %)]
                      ["-h" "--help" "Print this help." :flag true]
                      ["-i" "--input-compression"
                       "Receive compressed data. Available values: none, lzf, snappy"
                       :default "none"]
                      ["-m" "--merge-strategy"
                       "Strategy used for merging packets. Available strategies are: no-op, sort-by-timestamp"
                       :default "no-op"]
                      ["-o" "--output-compression"
                       "Optionally compress the emitted data. Available values: none, lzf, snappy"
                       :default "none"]
                      ["-q" "--queue-size"
                       (str "Size of packet queue."
                            "Determines how many packets are captured before a message is sent.")
                       :default 100
                       :parse-fn #(Integer. %)]
                      ["-s" "--stat-interval"
                       "Interval in milliseconds with which statistics are generated."
                       :default 500
                       :parse-fn #(Integer. ^java.lang.String %)]
                      ["-u" "--url" 
                       "URL used to connect to the broker." 
                       :default "tcp://127.0.0.1:61616"]
                      ["-I" "--id"
                       "An identifier that uniquely identifies the sensor instance."
                       :default "1"]
                      ["-M" "--maximum-queueing-time"
                       "Maximum time in miliseconds packets are kept in the queue."
                       :default 1000
                       :parse-fn #(Integer. %)]
                      ["-S" "--silent" "Omit most command line output." :flag true])
        arg-map (cli-args 0)
        extra-args (cli-args 1)
        help-string (cli-args 2)]
    (when (arg-map :help)
      (println help-string)
      (System/exit 0))
    (println "Starting packet merger using the following options:")
    (pprint arg-map)
    (pprint extra-args)
    (let
      [id (arg-map :id)
       input-compression (arg-map :input-compression)
       output-compression (arg-map :output-compression)
       url (arg-map :url)
       silent (atom (arg-map :silent))
       run-duration (arg-map :duration)
       ts-comparator (PcapByteArrayTimeStampComparator.)
       ^BlockingQueue merge-queue (condp = (arg-map :merge-strategy)
                     "sort-by-timestamp" (PriorityBlockingQueue. *queue-size* ts-comparator)
                     "no-op" (ArrayBlockingQueue. *queue-size*)
                     (PriorityBlockingQueue. *queue-size* ts-comparator))
       sensors (ref {})
       _ (doseq [sensor-id extra-args]
           (println "Adding sensor with id:" sensor-id)
           (add-sensor sensor-id url merge-queue sensors input-compression))
       topic-prefix (str "/topic/pcap.merged.raw." id)
       max-queueing-time (ref (arg-map :maximum-queueing-time))
       last-forced-queue-send-time (ref (System/currentTimeMillis))
       ^PooledBytesMessageProducer producer (activemq/create-pooled-bytes-message-producer url (str topic-prefix ".data") (arg-map :queue-size))
       _ (condp = output-compression
           "lzf" (doto producer
                   (.setCompress true)
                   (.setCompressionMethod PooledBytesMessageProducer$CompressionMethod/Lzf))
           "snappy" (doto producer
                      (.setCompress true)
                      (.setCompressionMethod PooledBytesMessageProducer$CompressionMethod/Snappy))
           nil)
       sent-counter (Counter.)
       send-data-fn #(let [^BytesMessagePayloadPart data (.take merge-queue)]
                       (.inc sent-counter)
                       (.send producer data))
       running (ref true)
       producer-fn #(try
                      (if @running
                        (SendHelper/sendData producer merge-queue *send-limit* sent-counter))
                      (catch Exception e
                        (if @running
                          (.printStackTrace e))))
       producer-thread (doto (ProcessingLoop. producer-fn)
                         (.setName "ProducerThread") (.setDaemon true) (.start))
       delta-cntr (delta-counter)
       monitor-producer (activemq/create-producer url (str topic-prefix ".monitor"))
       command-topic (str topic-prefix ".command")
       command-producer (activemq/create-producer url command-topic)
       cmd-rcvd-fn (fn [msg]
                     (if (= (type msg) java.lang.String)
                       (condp (fn [v c] (.startsWith c v)) msg
                         "reply" nil ; We ignore replies, for now.
                         "command"
                           (let [split-cmd (subvec (clojure.string/split msg #" ") 1)
                                 cmd (first split-cmd)
                                 args (clojure.string/join " " (rest split-cmd))]
                             (println "Got command:" cmd "and args:" args)
                             (condp = cmd
                               "add-sensor" (add-sensor args url merge-queue sensors input-compression)
                               "get-max-queueing-time" (command-producer (str "reply max-queueing-time " @max-queueing-time))
                               "get-sensors" (command-producer (str "reply sensors " (sort (keys @sensors))))
                               "remove-sensor" (let [sensor (@sensors args)]
                                                 ((:consumer sensor) :close)
                                                 (delta-cntr (keyword args) 0)
                                                 (dosync
                                                   (alter sensors dissoc args)))
                               "set-max-queueing-time" (let [new-time (read-string args)]
                                                         (if (and
                                                               (= (type new-time) java.lang.Long)
                                                               (> 0 new-time))
                                                           (dosync (ref-set max-queueing-time new-time))
                                                           (activemq/send-error-msg
                                                             command-producer
                                                             (str "Invalid max-queueing-time args: " args))))
                               (activemq/send-error-msg command-producer (str "Unknown command received: " cmd " Args: " args))))
                         (activemq/send-error-msg command-producer (str "Received invalid message: " msg)))
                       (activemq/send-error-msg
                         command-producer
                         (str "Received command message of wrong data type: " (type msg) " "
                              "Received data is: " msg))))
       command-consumer (activemq/create-consumer url command-topic cmd-rcvd-fn)
       stats-out-executor (executor)
       _ (run-repeat stats-out-executor (create-stats-fn sensors delta-cntr monitor-producer sent-counter silent) (arg-map :stat-interval))
       shutdown-fn (fn []
                     (println "Shuting down...")
                     (dosync (ref-set running false))
                     (shutdown-now stats-out-executor)
                     (.interrupt producer-thread)
                     (command-consumer :close)
                     (command-producer :close)
                     (monitor-producer :close)
                     (doseq [sensor-id (sort (keys @sensors))]
                       (let [consumer (get-in @sensors [sensor-id :consumer])]
                         (consumer :close)))
                     (.close producer))]
      (if (> run-duration 0)
        (do
          (println "Will automatically shut down in" run-duration "seconds.")
          (run-once (executor) shutdown-fn (* 1000 run-duration)))
        (do
          (println "Packet merger started.\nType \"q\" followed by <Return> to quit: ")
          ;;; Running the main from, e.g., leiningen results in stdout not being properly accessible.
          ;;; Hence, this will not work when run this way but works when run from a jar via "java -jar ...".
          (while (not= "q" (read-line))
            (println "Type \"q\" followed by <Return> to quit: "))
          (shutdown-fn))))))

