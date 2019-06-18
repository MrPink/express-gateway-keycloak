import { ExpressGateway } from 'express-gateway';
import { createLoggerWithLabel } from 'express-gateway/lib/logger';
import * as express from 'express';
import * as Keycloak from 'keycloak-connect';
import * as session from 'express-session';
import * as createMemoryStore from 'memorystore';

const logger = createLoggerWithLabel('[EG:plugin:keycloak]');

const MemoryStore = createMemoryStore(session);

interface IKeycloakPluginSettings {
  session?: any;
  keycloakConfig?: any;
}

const DefaultKeycloakPluginSettings: IKeycloakPluginSettings = {
  session: {
    secret: 'kc_secret'
  }
};

const KeycloakPlugin: ExpressGateway.Plugin = {
  version: '1.2.0',
  policies: ['keycloak-protect'],
  init: (ctx: ExpressGateway.PluginContext) => {
    // this is slightly dodgy casting, as they don't expose settings on the public interface - but not sure how else you can access custom settings for a plugin
    const sessionStore = new MemoryStore();
    const rawSettings: IKeycloakPluginSettings = (ctx as any).settings;
    const sessionSettings = {
      ...DefaultKeycloakPluginSettings.session,
      ...rawSettings.session,
      store: sessionStore
    };
    const keycloakConfig = {
      ...DefaultKeycloakPluginSettings.keycloakConfig,
      ...rawSettings.keycloakConfig
    };
    const pluginSettings: IKeycloakPluginSettings = {
      session: sessionSettings,
      keycloakConfig: keycloakConfig
    };
    const keycloak = new Keycloak(
      { store: sessionStore },
      pluginSettings.keycloakConfig
    );

    logger.info(
      `Initialized Keycloak Plugin with settings: ${JSON.stringify(
        pluginSettings,
        null,
        '\t'
      )}`
    );

    keycloak.authenticated = req => {
      logger.info(
        '-- Keycloak Authenticated: ' +
          JSON.stringify(req.kauth.grant.access_token.content, null, '\t')
      );
    };

    keycloak.accessDenied = (req, res) => {
      logger.info('-- Keycloak Access Denied');
      res.status(403).end('Access Denied');
    };

    // setup our keycloak middleware
    ctx.registerGatewayRoute(app => {
      logger.info('Registering Keycloak Middleware');
      app.use(session(pluginSettings.session));
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
            description:
              'the keycloak token variable name to reference the token in jsProtect',
            type: 'string'
          },
          jsProtect: {
            description: 'a js snippet to apply for whether a user has access.',
            type: 'string'
          }
        }
      },
      policy: (actionParams: any): express.RequestHandler => {
        logger.info(
          `-- Keycloak Protect: ${JSON.stringify(actionParams, null, '\t')}`
        );
        if (actionParams.jsProtect) {
          return keycloak.protect((token, req) => {
            req.egContext[actionParams.jsProtectTokenVar || 'token'] = token;
            const runResult = req.egContext.run(actionParams.jsProtect);
            logger.info('-- Keycloak Protect JS Result: ' + runResult);
            return runResult;
          });
        }
        return keycloak.protect(actionParams.role);
      }
    });
  },
  schema: {
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
        description:
          'This can be used rather than requiring keycloak.json to be present',
        type: 'object'
      }
    }
  }
};

export {
  IKeycloakPluginSettings,
  DefaultKeycloakPluginSettings,
  KeycloakPlugin,
  KeycloakPlugin as default
};
