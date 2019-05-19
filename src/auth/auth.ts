import { Request, Response, NextFunction } from "express";
import { v1 as Neo } from 'neo4j-driver';

export class Auth {
    middlewares = {
        auth: () => (req: Request, res: Response, next: NextFunction) => {
            this.services.augment(req);
            next();
        },
        isAuthenticated: () => (req: Request, res: Response, next: NextFunction) => {
            if (!req['AUTH'].authenticated) {
                res.status(401).send({ message: 'Not authenticated' });
            } else {
                next();
            }
        },
    };
    controllers = {
        signup: () => (req: Request, res: Response) => {
            res.send({ message: 'NIY' });
        },
        signin: () => (req: Request, res: Response) => {
            res.send({ message: 'NIY' });
        },
        signout: (withIsAuthenticated: boolean = true) => (req: Request, res: Response, next: NextFunction) => {
            if (withIsAuthenticated) {
                this.middlewares.isAuthenticated()(req, res, () => this.controllers.signout(false));
            }
            res.send({ message: 'NIY' });
        },
    };
    services = {
        getToken: (req: Request) => {},
        sign: (req: Request) => {},
        verify: (req: Request) => {},
        augment: (req: Request) => {
            const token = this.services.getToken(req);
            req['AUTH'] = Object.assign({}, {
                token,
                authenticated: true,
                user: undefined,
                roles: [],
            });
        },
        isAuthenticated: (req: Request) => {
            return !!req['AUTH'].authenticated;
        },
        getUser: (req: Request) => {
            return req['AUTH'].user;
        },
        getRoles: (req: Request) => {
            return req['AUTH'].roles || [];
        },
    };
    constructor(private driver: Neo.Driver) {}
}