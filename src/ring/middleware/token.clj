(ns ring.middleware.token
  (:require [cheshire.core :as json]
            [clojure.walk :refer [keywordize-keys]]
            [ring.middleware.jwk :as jwk]
            [clojure.spec.alpha :as s])
  (:import (com.auth0.jwt.algorithms Algorithm)
           (com.auth0.jwt JWT)
           (com.auth0.jwt.exceptions JWTDecodeException)
           (org.apache.commons.codec Charsets)
           (org.apache.commons.codec.binary Base64)
           (java.security PublicKey)))

(defn- base64->map
  [base64-str]
  (-> base64-str
      (Base64/decodeBase64)
      (String. Charsets/UTF_8)
      (json/parse-string)
      (keywordize-keys)))

(defn- decode-token*
  [algorithm token leeway]
  (-> algorithm
      (JWT/require)
      (.acceptLeeway (or leeway 0))
      (.build)
      (.verify token)
      (.getPayload)
      (base64->map)))

(s/def ::alg #{:RS256 :HS256})
(s/def ::leeway nat-int?)

(s/def ::secret (s/and string? (complement clojure.string/blank?)))
(s/def ::secret-opts (s/and (s/keys :req-un [::alg ::secret])
                            #(contains? #{:HS256} (:alg %))))

(s/def ::public-key #(instance? PublicKey %))
(s/def ::jwk-endpoint (s/and string? #(re-matches #"(?i)^https?://.+$" %)))
(s/def ::key-id (s/and string? (complement clojure.string/blank?)))
(s/def ::public-key-opts (s/and #(contains? #{:RS256} (:alg %))
                                (s/or :key (s/keys :req-un [::alg ::public-key])
                                      :url (s/keys :req-un [::alg ::jwk-endpoint ::key-id]))))

(defmulti decode
          "Decodes and verifies the signature of the given JWT token. The decoded claims from the token are returned."
          (fn [_ {:keys [alg]}] alg))
(defmethod decode nil
  [& _]
  (throw (JWTDecodeException. "Could not parse algorithm.")))

(defmethod decode :RS256
  [token {:keys [public-key jwk-endpoint key-id leeway-seconds] :as opts}]
  {:pre [(s/valid? ::public-key-opts opts)]}

  (let [[public-key-type _] (s/conform ::public-key-opts opts)]
    (-> (Algorithm/RSA256 (case public-key-type
                            :url (jwk/get-jwk jwk-endpoint key-id)
                            :key public-key))
        (decode-token* token leeway-seconds))))

(defmethod decode :HS256
  [token {:keys [secret leeway-seconds] :as opts}]
  {:pre [(s/valid? ::secret-opts opts)]}
  (-> (Algorithm/HMAC256 secret)
      (decode-token* token leeway-seconds)))