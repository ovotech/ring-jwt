(ns ring.middleware.jwt
  (:require [clojure.spec.alpha :as s]
            [ring.middleware.token :as token])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException AlgorithmMismatchException JWTVerificationException TokenExpiredException)))

(defn read-token-from-header
  "Finds the token by searching the specified HTTP header (case-insensitive) for a bearer token."
  [header-name]
  (fn [{:keys [headers]}]
    (some->> headers
             (filter #(.equalsIgnoreCase header-name (key %)))
             (first)
             (val)
             (re-find #"(?i)^Bearer (.+)$")
             (last))))

(s/def ::alg-opts (s/and (s/keys :req-un [::token/alg]
                                 :opt-un [::token/leeway-seconds])
                         (s/or :secret-opts ::token/secret-opts
                               :public-key-opts ::token/public-key-opts)))
(s/def ::issuers (s/map-of ::token/issuer ::alg-opts))
(s/def ::find-token-fn ifn?)
(s/def ::reject-missing-token? boolean?)

(s/def ::opts (s/keys :req-un [::issuers]
                      :opt-un [::find-token-fn ::reject-missing-token?]))

(defn wrap-jwt
  "Middleware that decodes a JWT token, verifies against the signature and then
  adds the decoded claims to the incoming request under :claims.

  If the JWT token exists but cannot be decoded then the token is considered tampered with and
  a 401 response is produced.

  If the JWT token does not exist, an empty :claims map is added to the incoming request."
  [handler {:keys [find-token-fn issuers reject-missing-token?]
            :or   {reject-missing-token? false}
            :as   opts}]
  (when-not (s/valid? ::opts opts)
    (throw (ex-info "Invalid options." (s/explain-data ::opts opts))))

  (fn [req]
    (try
      (if-let [token ((or find-token-fn (read-token-from-header "Authorization")) req)]
        (if-let [alg-opts (or (->> token token/decode-issuer (get issuers)) (get issuers "catch-all"))]
          (->> (token/decode token alg-opts)
               (assoc req :claims)
               (handler))
          {:status 401
           :body   "Unknown issuer."})

        (if reject-missing-token?
          {:status 401
           :body   "No token found."}
          (->> (assoc req :claims {})
               (handler))))

      (catch JWTVerificationException e
        {:status 401
         :body   (ex-message e)}))))

(s/fdef wrap-jwt
        :ret fn?
        :args (s/cat :handler fn?
                     :opts ::opts))
