(ns ring.middleware.jwt
  (:require [clojure.spec.alpha :as s]
            [ring.middleware.token :as token])
  (:import (com.auth0.jwt.exceptions SignatureVerificationException AlgorithmMismatchException JWTVerificationException TokenExpiredException)))

(defn- find-token
  [{:keys [headers]}]
  (some->> headers
           (filter #(.equalsIgnoreCase "authorization" (key %)))
           (first)
           (val)
           (re-find #"(?i)^Bearer (.+)$")
           (last)))

(s/def ::alg-opts (s/and (s/keys :req-un [::token/alg]
                                 :opt-un [::token/leeway-seconds ::token/issuer ::token/finder])
                         (s/or :secret-opts ::token/secret-opts
                               :public-key-opts ::token/public-key-opts)))

(defn wrap-jwt
  "Middleware that decodes a JWT token, verifies against the signature and then
  adds the decoded claims to the incoming request under :claims.

  If the JWT token exists but cannot be decoded then the token is considered tampered with and
  a 401 response is produced.

  If the JWT token does not exist, an empty :claims map is added to the incoming request."
  [handler {:keys [finder] :or {finder find-token} :as opts}]
  (when (not (s/valid? ::alg-opts opts))
    (throw (ex-info "Invalid options." (s/explain-data ::alg-opts opts))))

  (fn [req]
    (try
      (if-let [token (finder req)]
        (->> (token/decode token opts)
             (assoc req :claims)
             (handler))
        (->> (assoc req :claims {})
             (handler)))

      (catch SignatureVerificationException _
        {:status 401
         :body   "Signature could not be verified."})

      (catch AlgorithmMismatchException _
        {:status 401
         :body   "Signature could not be verified."})

      (catch TokenExpiredException _
        {:status 401
         :body   "Token has expired."})

      (catch JWTVerificationException _
        {:status 401
         :body   "One or more claims were invalid."}))))

(s/fdef wrap-jwt
        :ret fn?
        :args (s/cat :handler fn?
                     :opts ::alg-opts))
