"use strict";
var __assign = (this && this.__assign) || function () {
    __assign = Object.assign || function(t) {
        for (var s, i = 1, n = arguments.length; i < n; i++) {
            s = arguments[i];
            for (var p in s) if (Object.prototype.hasOwnProperty.call(s, p))
                t[p] = s[p];
        }
        return t;
    };
    return __assign.apply(this, arguments);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
var keycloak_connect_multirealm_1 = __importDefault(require("keycloak-connect-multirealm"));
var logger_1 = require("express-gateway/lib/logger");
var memorystore_1 = __importDefault(require("memorystore"));
var express_session_1 = __importDefault(require("express-session"));
var logger = logger_1.createLoggerWithLabel('[EG:plugin:keycloak]');
var MemoryStore = memorystore_1.default(express_session_1.default);
exports.defaultRealmConfig = {
    in: 'routeParam',
    key: 'realm'
};
exports.DefaultKeycloakPluginSettings = {
    session: {
        secret: 'kc_secret'
    },
    realm: exports.defaultRealmConfig
};
var KeycloakPlugin = /** @class */ (function () {
    function KeycloakPlugin() {
        var _this = this;
        this.version = '1.2.0';
        this.policies = ['keycloak-protect'];
        this.init = function (ctx) {
            // this is slightly dodgy casting, as they don't expose settings on the public interface - but not sure how else you can access custom settings for a plugin
            var sessionStore = new MemoryStore();
            var rawSettings = ctx.settings;
            var sessionSettings = __assign({}, exports.DefaultKeycloakPluginSettings.session, rawSettings.session, { store: sessionStore });
            var keycloakConfig = __assign({}, exports.DefaultKeycloakPluginSettings.keycloakConfig, rawSettings.keycloakConfig);
            var realmConfig = rawSettings.realm;
            var pluginSettings = {
                realm: realmConfig,
                session: sessionSettings,
                keycloakConfig: keycloakConfig
            };
            var keycloak = new keycloak_connect_multirealm_1.default({ store: sessionStore }, pluginSettings.keycloakConfig);
            logger.info("Initialized Keycloak Plugin with settings: " + JSON.stringify(pluginSettings, null, '\t'));
            keycloak.authenticated = function (req) {
                logger.info('-- Keycloak Authenticated: ' +
                    JSON.stringify(req.kauth.grant.access_token.content, null, '\t'));
            };
            keycloak.accessDenied = function (_req, res) {
                logger.info('-- Keycloak Access Denied');
                res.status(403).end('Access Denied');
            };
            keycloak.getRealmNameFromRequest = function (req) {
                return _this.getRealmName(req, realmConfig);
            };
            // setup our keycloak middleware
            ctx.registerGatewayRoute(function (app) {
                logger.info('Registering Keycloak Middleware');
                app.use(express_session_1.default(pluginSettings.session));
                app.use(keycloak.middleware());
            });
            ctx.registerPolicy({
                name: 'keycloak-protect',
                schema: {
                    $id: 'http://express-gateway.io/schemas/policies/keycloak-protect.json',
                    type: 'object',
                    properties: {
                        role: {
                            description: 'the keycloak role to restrict access to',
                            type: 'string'
                        },
                        jsProtectTokenVar: {
                            description: 'the keycloak token variable name to reference the token in jsProtect',
                            type: 'string'
                        },
                        jsProtect: {
                            description: 'a js snippet to apply for whether a user has access.',
                            type: 'string'
                        }
                    }
                },
                policy: function (actionParams) {
                    logger.info("-- Keycloak Protect: " + JSON.stringify(actionParams, null, '\t'));
                    if (actionParams.jsProtect) {
                        return keycloak.protect(function (token, req) {
                            req.egContext[actionParams.jsProtectTokenVar || 'token'] = token;
                            var runResult = req.egContext.run(actionParams.jsProtect);
                            logger.info('-- Keycloak Protect JS Result: ' + runResult);
                            return runResult;
                        });
                    }
                    return keycloak.protect(actionParams.role);
                }
            });
        };
        this.getRealmName = function (req, realmConfig) {
            var realm;
            switch (realmConfig.in) {
                case 'path':
                    realm =  (req.originalUrl.split('/')[0] || '').toString();
                case 'routeParam':
                    realm = (req.params[realmConfig.key] || '').toString();
                case 'header':
                    realm = (req.get(realmConfig.key) || '').toString();
                case 'query':
                    realm = (req.query[realmConfig.key] || '').toString();
                case 'body':
                    realm = (req.body ? req.body[realmConfig.key] || '' : '').toString();
                default:
                    logger.info("Path \"" + req.path + "\" does not specify a Keycloak realm");
                    realm = '';
            }
            return realm;
        };
    }
    Object.defineProperty(KeycloakPlugin.prototype, "schema", {
        get: function () {
            return {
                $id: 'http://express-gateway.io/schemas/plugin/keycloak.json',
                type: 'object',
                properties: {
                    session: {
                        title: 'Session Settings',
                        description: 'Session Settings as outlined by express middleware',
                        type: 'object'
                    },
                    keycloakConfig: {
                        title: 'Keycloak Configuration',
                        description: 'This can be used rather than requiring keycloak.json to be present',
                        type: 'object'
                    }
                }
            };
        },
        enumerable: true,
        configurable: true
    });
    return KeycloakPlugin;
}());
exports.default = KeycloakPlugin;
