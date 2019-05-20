import dotenv from 'dotenv';
import fs from 'fs';
import cors from 'cors';
import bodyParser from 'body-parser';
import express, { Request, Response } from 'express';
import { ApolloServer, makeExecutableSchema } from 'apollo-server-express';
import { v1 as Neo } from 'neo4j-driver';
import { makeAugmentedSchema, augmentSchema, neo4jgraphql } from 'neo4j-graphql-js';
import { Auth } from './auth/auth';
import { resolvers } from './resolvers';
import { schemaDirectives, directiveRegister } from './directives/schema-directives';
import { PassportJwt } from './auth/passport-jwt';
import passport from 'passport';

dotenv.config();

const {
    SRV_PATH,
    SRV_PORT,
    NEO_URI,
    NEO_USR,
    NEO_PWD,
    GQL_FILE,
    PLAYGROUND,
} = process.env;

const app = express();
const driver = Neo.driver(NEO_URI, Neo.auth.basic(NEO_USR, NEO_PWD));
// const auth = new Auth(driver);

const baseSchema = makeAugmentedSchema({
    typeDefs: fs.readFileSync(GQL_FILE, 'utf8'),
    schemaDirectives: schemaDirectives,
    resolvers: resolvers,
    config: {
        query: { exclude: [] },
        mutation: { exclude: [] },
    },
});

const schema = baseSchema; // makeLastAugmentationInSchema({ schema: baseSchema });

directiveRegister.compute(schema);

app.use(
    cors(),
    bodyParser.json(),
    bodyParser.urlencoded({ extended: true }),
    (req, res, next) => {
        if (req.query && req.query.token) {
            req.headers.authorization = `Bearer ${req.query.token}`;
        }
        next();
    }
    // auth.middlewares.auth(),
);

const auth = new PassportJwt(app, driver);

const context = ({ req, res }: { req: Request, res: Response }) => ({
    req, res, driver, auth, neo4jgraphql
});

app.post('/signup', auth.signup());
app.post('/signin', auth.signin());

app.get(
    '/public',
    (req, res) => res.send({ message: 'This is public' })
);

app.get(
    '/private',
    passport.authenticate('jwt', { session: false }),
    (req, res) => res.send({ message: 'This is private' })
);

// app.use('/signout', auth.controllers.signout());

const server = new ApolloServer({ schema, context, playground: !!PLAYGROUND });
server.applyMiddleware({ app, path: SRV_PATH });

app.listen({ port: SRV_PORT }, () => {
    console.log(`Server listening at http://localhost:${SRV_PORT}${SRV_PATH}`);
});
