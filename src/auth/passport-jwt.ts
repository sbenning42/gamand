import { Application, Request, Response, NextFunction } from "express";
import passport from 'passport';
import passportJwt from 'passport-jwt';
import jwt from 'jsonwebtoken';
import { v1 as Neo } from 'neo4j-driver';

export class PassportJwt {
    constructor(
        app: Application,
        private driver: Neo.Driver,
    ) {
        app.use(passport.initialize());
        const { Strategy, ExtractJwt } = passportJwt;
        const opts = {
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.JWT_SECRET,
        };
        passport.use(new Strategy(opts, (payload, done) => {
            const { id } = payload;
            if (!id) {
                done(null, false);
                return;
            }
            const session = driver.session();
            const closeSession = () => session.close();
            const cypher = `
                MATCH
                    (u: User { id: "${id}" }),
                    (u)-[:HAS]->(rs: Role),
                    (u)-[:OWN]->(c: Credentials),
                    (u)-[:OWN]->(p: Profil)
                RETURN u {
                    .id,
                    credentials: c { .id, .email, .password },
                    profil: p { .id, .email, .name, .birthdate },
                    roles: collect(rs { .id, .name })
                } as user
                LIMIT 1
            `;
            session.run(cypher).then(({ records: { 0: result } }) => {
                const user = result && result.get('user');
                if (user) {
                    done(null, user);
                } else {
                    done({ message: `No user ...` }, false);
                }
            }, error => {
                done(error, false);
            }).finally(closeSession);
        }));
    }

    signup() {
        return (req: Request, res: Response, next: NextFunction) => {
            const missings = ['email', 'password', 'name'].filter(required => req.body[required] === undefined);
            if (missings.length > 0) {
                res.status(400).send({ message: `Fields ${missings} missing` });
                return;
            }
            const { email, password, name } = req.body;
            const session = this.driver.session();
            const closeSession = () => session.close();
            const cypherFind = `
                MATCH
                    (u: User)-[:OWN]->(:Credentials { email: "${email}" })
                RETURN u { .id } as user
                LIMIT 1
            `;
            const cypherCreate = `
                MATCH (r: Role { name: "user" })
                CREATE
                    (c: Credentials { id: apoc.create.uuid(), email: "${email}", password: "${password}" }),
                    (p: Profil { id: apoc.create.uuid(), email: "${email}", name: "${name}", birthdate: date() }),
                    (u: User { id: apoc.create.uuid() }),
                    (u)-[:HAS { createdAt: date() }]->(r),
                    (u)-[:OWN { createdAt: date() }]->(c),
                    (u)-[:OWN { createdAt: date() }]->(p)
                RETURN u {
                    .id,
                    profil: p { .id, .email, .name, .birthdate },
                    roles: [r { .id, .name }]
                } as user
                LIMIT 1
            `;
            session.run(cypherFind).then(({ records: { 0: findResult } }) => {
                const foundUser = findResult && findResult.get('user');
                if (foundUser) {
                    res.status(401).send({ message: `Email already in use` });
                    return;
                }
                return session.run(cypherCreate).then(({ records: { 0: createResult } }) => {
                    const user = createResult && createResult.get('user');
                    if (!user) {
                        res.status(500).send({ message: `Something went wrong` });
                        return;                        
                    }
                    res.send({ user });
                });
            }, error => {
                res.status(500).send({ message: `Something went wrong`, error });
            }).finally(closeSession);
        };
    }

    
    signin() {
        return (req: Request, res: Response, next: NextFunction) => {
            const missings = ['email', 'password'].filter(required => req.body[required] === undefined);
            if (missings.length > 0) {
                res.status(400).send({ message: `Fields ${missings} missing` });
                return;
            }
            const { email, password } = req.body;
            const session = this.driver.session();
            const closeSession = () => session.close();
            const cypherFind = `
                MATCH
                    (u: User)-[:OWN]->(c: Credentials { email: "${email}" }),
                    (u)-[:HAS]->(rs: Role),
                    (u)-[:OWN]->(p: Profil)
                RETURN
                    u {
                        .id,
                        profil: p { .id, .email, .name, .birthdate },
                        roles: collect(rs { .id, .name })
                    } as user,
                    c { .id, .email, .password } as credentials
                LIMIT 1
            `;
            session.run(cypherFind).then(({ records: { 0: findResult } }) => {
                const user = findResult && findResult.get('user');
                const credentials = findResult && findResult.get('credentials');
                if (!user || !(credentials.password === password)) {
                    res.status(401).send({ message: `Wrong credentials` });
                    return;
                }
                const token = jwt.sign({ user, id: user.id }, process.env.JWT_SECRET);
                res.send({ user, token });
            }, error => {
                res.status(500).send({ message: `Something went wrong`, error });
            }).finally(closeSession);
        };
    }

    


}
