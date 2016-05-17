angular.module('angular.plugins.oauth', [])

.provider('$oauth', function() {
	var oauthConsumerKey, oauthConsumerSecret, oauthToken, oauthTokenSecret;

	this.consumerKey = function(value) {
		if (value) {
			oauthConsumerKey = value;
			return this;
		} else {
			return oauthConsumerKey;
		}
	};

	this.consumerSecret = function(value) {
		if (value) {
			oauthConsumerSecret = value;
			return this;
		} else {
			return oauthConsumerSecret;
		}
	};

	var percentDecode = decodeURIComponent;

	var percentEncode = function(str) {
		return ('' + str).replace(/[^a-z0-9-._~]/gi, function(chr) {
			return '%' + chr.charCodeAt(0).toString(16).toUpperCase();
		});
	};

	var normalizeVars = function(vars) {
		var params = [];

		var keys = Object.keys(vars);
		keys.sort();

		for (var index in keys) {
			var key = keys[index];
			params.push(percentEncode(key) + '=' + percentEncode(vars[key]));
		}

		return params.join('&');
	};

	var mergeVars = function() {
		var vars = {};

		for (var argIndex in arguments) {
			var obj = arguments[argIndex];
			var keys = Object.keys(obj);

			for (var index in keys) {
				var key = keys[index];

				if (!vars.hasOwnProperty(key))
					vars[key] = obj[key];
			}
		}

		return vars;
	};

	var randomNonce = function(numBytes) {
		var hex = [];

		for (var i = 0; i < numBytes; i++) {
			var byte = Math.floor(Math.random() * 0xFF);
			hex.push((byte < 16 ? '0' : '') + byte.toString(16));
		}

		return hex.join('');
	};

	var signRequest = function(method, uri, query) {
		var oauthVars = {
			oauth_consumer_key: oauthConsumerKey,
			oauth_signature_method: 'HMAC-SHA1',
			oauth_timestamp: Math.floor(Date.now() / 1000),
			oauth_nonce: randomNonce(16),
			oauth_version: '1.0'
		};

		if (oauthToken)
			oauthVars.oauth_token = oauthToken;

		var params = mergeVars(oauthVars, query || {});

		oauthVars.oauth_signature = createSignature(method, uri, params);

		return oauthVars;
	};

	var createSignature = function(method, uri, params) {
		var message = [
			method.toUpperCase(),
			percentEncode(uri),
			percentEncode(normalizeVars(params))
		].join('&');

		var key = oauthConsumerSecret + '&';

		if (oauthTokenSecret)
			key += oauthTokenSecret;

		var hmac = CryptoJS.HmacSHA1(message, key);

		return CryptoJS.enc.Base64.stringify(hmac);
	};

	var createHeader = function(method, uri, query) {
		var params = signRequest(method, uri, query);
		var header = [];

		for (var key in params)
			header.push(key + '="' + params[key] + '"');

		return 'OAuth ' + header.join(', ');
	};

	var buildQuery = function(params) {
		var pairs = [];

		for (var key in params) {
			pairs.push(percentEncode(key) + '=' + percentEncode(params[key]));
		}

		return pairs.join('&');
	};

	var parseQuery = function(query) {
		var params = {};

		query.split('&').forEach(function(pair) {
			var pieces = pair.split('=');
			params[percentDecode(pieces[0])] = percentDecode(pieces[1]);
		});

		return params;
	};

	var resetToken = function() {
		oauthToken = null;
		oauthTokenSecret = null;
	};

	this.$get = ['$rootScope', '$http', '$q', function($rootScope, $http, $q) {
		return {
			get: function(uri) {
				var a = document.createElement('a');
				a.href = uri;

				var rawuri = a.origin + a.pathname;
				var query = a.search ? parseQuery(a.search.substr(1)) : [];

				return $http.get(uri, {
					headers: {
						'Authorization': createHeader('GET', rawuri, query)
					},
					withCredentials: true
				});
			},
			post: function(uri, query) {
				return $http.post(uri, buildQuery(query), {
					headers: {
						'Authorization': createHeader('POST', uri, query),
						'Content-Type': 'application/x-www-form-urlencoded'
					},
					withCredentials: true
				});
			},
			reset: function() {
				resetToken();
				$rootScope.$broadcast('oauth.reset_token');
			},
			consumerKey: function(value) {
				if (value) {
					oauthConsumerKey = value;
					return this;
				} else {
					return oauthConsumerKey;
				}
			},
			consumerSecret: function(value) {
				if (value) {
					oauthConsumerSecret = value;
					return this;
				} else {
					return oauthConsumerSecret;
				}
			},
			token: function(value) {
				if (value) {
					oauthToken = value;
					return this;
				} else {
					return oauthToken;
				}
			},
			tokenSecret: function(value) {
				if (value) {
					oauthTokenSecret = value;
					return this;
				} else {
					return oauthTokenSecret;
				}
			}
		};
	}];
});
