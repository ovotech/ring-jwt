(ns ring.middleware.jwt-test
  (:require [cheshire.core :as json]
            [clojure.string :refer [split join]]
            [clojure.test :refer :all]
            [ring.middleware.jwt-test-utils :as util]
            [ring.middleware.jwt :refer [wrap-jwt]])
  (:import (clojure.lang ExceptionInfo)
           (java.util UUID)))

(def ^:private dummy-handler (constantly identity))

(defn- build-request
  [claims alg-opts]
  (util/add-jwt-token {} claims alg-opts))

(defn- epoch-seconds
  []
  (int (/ (System/currentTimeMillis) 1000)))

(deftest claims-from-valid-jwt-token-in-authorization-header-are-added-to-request
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims  {:a 1 :b 2}
        handler (wrap-jwt (dummy-handler) {:alg        :RS256
                                           :public-key public-key})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest jwt-token-signed-with-wrong-algorithm-causes-401
  (let [{:keys [private-key]} (util/generate-key-pair :RS256)
        claims  {:a 1 :b 2}
        handler (wrap-jwt (dummy-handler) {:alg    :HS256
                                           :secret (util/generate-hmac-secret)})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Signature could not be verified." body))))

(deftest jwt-token-with-tampered-header-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims          {:a 1 :b 2}
        token           (util/encode-token claims {:alg       :RS256
                                                 :private-key private-key})
        [_ payload signature] (split token #"\.")
        tampered-header (util/str->base64 (json/generate-string {:alg :RS256 :a 1}))
        tampered-token  (join "." [tampered-header payload signature])

        handler         (wrap-jwt (dummy-handler) {:alg        :RS256
                                                   :public-key public-key})
        req             {:headers {"Authorization" (str "Bearer " tampered-token)}}
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Signature could not be verified." body))))

(deftest jwt-token-with-tampered-payload-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims           {:a 1 :b 2}
        token            (util/encode-token claims {:alg       :RS256
                                                  :private-key private-key})

        [header _ signature] (split token #"\.")
        tampered-payload (util/str->base64 (json/generate-string {:a 1}))
        tampered-token   (join "." [header tampered-payload signature])

        handler          (wrap-jwt (dummy-handler) {:alg        :RS256
                                                    :public-key public-key})
        req              {:headers {"Authorization" (str "Bearer " tampered-token)}}
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Signature could not be verified." body))))

(deftest no-jwt-token-causes-empty-claims-map-added-to-request
  (let [handler (wrap-jwt (dummy-handler) {:alg    :HS256
                                           :secret "whatever"})
        req     {:some "data"}
        res     (handler req)]
    (is (= req (dissoc res :claims)))
    (is (= {} (:claims res)))))

(deftest expired-jwt-token-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims  {:exp (- (epoch-seconds) 1)}
        handler (wrap-jwt (dummy-handler) {:alg        :RS256
                                           :public-key public-key})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "Token has expired." body))))

(deftest future-active-jwt-token-causes-401
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims  {:nbf (+ (epoch-seconds) 1)}
        handler (wrap-jwt (dummy-handler) {:alg        :RS256
                                           :public-key public-key})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        {:keys [body status]} (handler req)]
    (is (= 401 status))
    (is (= "One or more claims were invalid." body))))

(deftest expired-jwt-token-within-specified-leeway-is-valid
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims  {:exp (- (epoch-seconds) 100)}
        handler (wrap-jwt (dummy-handler) {:alg            :RS256
                                           :public-key     public-key
                                           :leeway-seconds 1000})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        res     (handler req)]
    (is (= claims (:claims res)))))

(deftest future-jwt-token-within-specified-leeway-is-valid
  (let [{:keys [private-key public-key]} (util/generate-key-pair :RS256)
        claims  {:nbf (+ (epoch-seconds) 100)}
        handler (wrap-jwt (dummy-handler) {:alg            :RS256
                                           :public-key     public-key
                                           :leeway-seconds 1000})
        req     (build-request claims {:alg         :RS256
                                       :private-key private-key})
        res     (handler req)]
    (is (= claims (:claims res)))))

(testing "invalid options"
  (deftest missing-option-causes-error
    (is (thrown-with-msg? ExceptionInfo #"Invalid options."
                          (wrap-jwt (dummy-handler) {:alg    :HS256
                                                     :bollox "whatever"}))))

  (deftest incorrect-option-type-causes-error
    (is (thrown-with-msg? ExceptionInfo #"Invalid options."
                          (wrap-jwt (dummy-handler) {:alg    :HS256
                                                     :secret 1}))))

  (deftest option-from-wrong-algorithm-causes-error
    (is (thrown-with-msg? ExceptionInfo #"Invalid options."
                          (wrap-jwt (dummy-handler) {:alg    :RS256
                                                     :secret "whatever"}))))

  (deftest extra-unsupported-option-does-not-cause-error
    (wrap-jwt (dummy-handler) {:alg    :HS256
                               :secret "somesecret"
                               :bollox "whatever"}))

  (deftest http-protocol-in-jwk-endpoint-does-not-cause-error
    (wrap-jwt (dummy-handler) {:alg          :RS256
                               :jwk-endpoint "http://my/jwk"
                               :key-id       (str (UUID/randomUUID))})))
