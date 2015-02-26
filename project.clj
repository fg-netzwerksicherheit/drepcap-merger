(defproject drepcap-merger "1.0.0"
  :description "DRePCap Merger Component"
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [org.clojure/tools.cli "0.2.4"]
                 [clj-assorted-utils "1.7.0"]
                 [clj-net-pcap "1.6.9995"]
                 [fg-netzwerksicherheit/clj-jms-activemq-toolkit "1.0.0"]
                 [org.slf4j/slf4j-simple "1.5.11"]]
  :global-vars {*warn-on-reflection* true}
  :license {:name "Eclipse Public License (EPL) - v 1.0"
            :url "http://www.eclipse.org/legal/epl-v10.html"
            :distribution :repo
            :comments "This is the same license as used for Clojure."}
  :java-source-paths ["src-java"]
  :main drepcap.merger.main)

