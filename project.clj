(defproject ovotech/ring-jwt "0.1.0"
  :description "JWT middleware for Ring"
  :url "http://github.com/ovotech/ring-jwt"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[cheshire "5.8.0"]
                 [commons-codec "1.11"]
                 [org.clojure/clojure "1.9.0"]
                 [org.clojure/core.cache "0.7.1"]
                 [com.auth0/java-jwt "3.3.0"]
                 [com.auth0/jwks-rsa "0.4.0"]]
  :profiles {:dev {:dependencies [[org.clojure/test.check "0.9.0"]]
                   :eftest       {:multithread? false}
                   :plugins      [[lein-eftest "0.4.3"]]}})
