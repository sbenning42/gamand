import { SchemaDirectiveVisitor } from "graphql-tools";
import { GraphQLObjectType, GraphQLField, GraphQLSchema, DirectiveNode } from "graphql";

import passport from 'passport';

export class RegisterDirective {
    private mapping: {
        [name: string]: { objectType: GraphQLObjectType, forArgValues: string[], visitor: SchemaDirectiveVisitor }[];
    } = {};
    register(name: string, objectType: GraphQLObjectType, forArgValues: string[], visitor: SchemaDirectiveVisitor) {
        if (!this.mapping[name]) {
            this.mapping[name] = [{ objectType, forArgValues, visitor }];
        } else {
            this.mapping[name].push({ objectType, forArgValues, visitor });
        }
    }
    compute(schema: GraphQLSchema) {
        const mapped: any = {};
        Object.keys(this.mapping).forEach(directiveName => {
            const objects = this.mapping[directiveName];
            objects.forEach(({ objectType, forArgValues, visitor }) => {
                const name = objectType.name;
                // console.log(`Should change mutations and queries for ${name}@${directiveName}`);
                const mutations = schema.getMutationType().getFields();
                const queries = schema.getQueryType().getFields();
                const emptyPattern = { startsWith: `EMPTY`, includes: `EMPTY PATTERN SHOULD NOT BE USED` };
                const mutationPatterns = [
                    forArgValues.includes('all') || forArgValues.includes('mutations') || forArgValues.includes('create') ? { startsWith: `Create${name}`, includes: `` } : emptyPattern,
                    forArgValues.includes('all') || forArgValues.includes('mutations') || forArgValues.includes('update') ? { startsWith: `Update${name}`, includes: `` } : emptyPattern,
                    forArgValues.includes('all') || forArgValues.includes('mutations') || forArgValues.includes('delete') ? { startsWith: `Delete${name}`, includes: `` } : emptyPattern,
                    forArgValues.includes('all') || forArgValues.includes('mutations') || forArgValues.includes('add') ? { startsWith: `Add`, includes: `${name}` } : emptyPattern,
                    forArgValues.includes('all') || forArgValues.includes('mutations') || forArgValues.includes('remove') ? { startsWith: `Remove`, includes: `${name}` } : emptyPattern,
                ];
                Object.keys(queries).forEach(queryName => {
                    if ((forArgValues.includes('all') || forArgValues.includes('read') || forArgValues.includes('query')) && queryName === name) {
                        console.log(`Has grabbed ${queryName} for ${name}@${directiveName}`);
                        const query = queries[queryName];
                        const thisDirective = objectType.astNode.directives.find(directive => directive.name.value === (visitor as any)._name);
                        (visitor.visitFieldDefinition as any)(query, undefined, thisDirective);
                    }
                });
                Object.keys(mutations).forEach(mutationName => {
                    if (mutationPatterns.some(
                        pattern => mutationName.startsWith(pattern.startsWith) && mutationName.includes(pattern.includes)
                    )) {
                        console.log(`Has grabbed ${mutationName} for ${name}@${directiveName}`);
                        const mutation = mutations[mutationName];
                        const thisDirective = objectType.astNode.directives.find(directive => directive.name.value === (visitor as any)._name);
                        (visitor.visitFieldDefinition as any)(mutation, undefined, thisDirective);
                    }
                });
            });
        });
    }
}

export const directiveRegister = new RegisterDirective();

export class AuthDirective extends SchemaDirectiveVisitor {
    _wrappedFields = {};
    _name = 'auth';
    visitObject(objectType: GraphQLObjectType) {
        const thisDirective = objectType.astNode.directives.find(directive => directive.name.value === this._name);
        const forArg = thisDirective.arguments.find(arg => arg.name.value === 'for');
        const forArgValues = (forArg.value as any).values.map(v => v && v.value);
        directiveRegister.register(this._name, objectType, forArgValues, this);
        if (forArgValues.includes('all') || forArgValues.includes('read') || forArgValues.includes('query')) {
            const fields = objectType.getFields();
            Object.keys(fields).forEach(fieldName => this.visitFieldDefinition(fields[fieldName], {objectType}, thisDirective));
        }
    }
    visitFieldDefinition(field: GraphQLField<any, any>, details?: { objectType: GraphQLObjectType }, directive?: DirectiveNode) {
        const original = field.resolve;
        field.resolve = (parent: any, args: any, ctx: any, infos: any) => {
            return new Promise((resolve, reject) => {
                const currentUser = ctx.req.user;
                passport.authenticate('jwt', { session: false })(ctx.req, ctx.res, () => {
                    ctx.req.user = currentUser || ctx.req.user;
                    resolve(original.apply(this, [parent, args, ctx, infos]));
                });
            });
        };
    }
}

export class AdminDirective extends SchemaDirectiveVisitor {
    _wrappedFields = {};
    _name = 'admin';
    visitObject(objectType: GraphQLObjectType) {
        const thisDirective = objectType.astNode.directives.find(directive => directive.name.value === this._name);
        const forArg = thisDirective.arguments.find(arg => arg.name.value === 'for');
        const forArgValues = (forArg.value as any).values.map(v => v && v.value);
        directiveRegister.register(this._name, objectType, forArgValues, this);
        if (forArgValues.includes('all') || forArgValues.includes('read') || forArgValues.includes('query')) {
            const fields = objectType.getFields();
            Object.keys(fields).forEach(fieldName => this.visitFieldDefinition(fields[fieldName], {objectType}, thisDirective));
        }
    }
    visitFieldDefinition(field: GraphQLField<any, any>, details?: { objectType: GraphQLObjectType }, directive?: DirectiveNode) {
        const original = field.resolve;
        field.resolve = (parent: any, args: any, ctx: any, infos: any) => {
            return new Promise((resolve, reject) => {
                const currentUser = ctx.req.user;
                passport.authenticate('jwt', { session: false })(ctx.req, ctx.res, () => {
                    ctx.req.user = currentUser || ctx.req.user;
                    if (ctx.req.user.roles.some(role => role.name === 'admin')) {
                        resolve(original.apply(this, [parent, args, ctx, infos]));
                    } else {
                        ctx.res.status(401);
                        reject(new Error('Not authorized'));
                    }
                });
            });
        };
    }
}

export class HasRoleDirective extends SchemaDirectiveVisitor {
    _wrappedFields = {};
    _name = 'hasRole';
    visitObject(objectType: GraphQLObjectType) {
        const thisDirective = objectType.astNode.directives.find(directive => directive.name.value === this._name);
        const forArg = thisDirective.arguments.find(arg => arg.name.value === 'for');
        const forArgValues = (forArg.value as any).values.map(v => v && v.value);
        directiveRegister.register(this._name, objectType, forArgValues, this);
        if (forArgValues.includes('all') || forArgValues.includes('read') || forArgValues.includes('query')) {
            const fields = objectType.getFields();
            Object.keys(fields).forEach(fieldName => this.visitFieldDefinition(fields[fieldName], {objectType}, thisDirective));
        }
    }
    visitFieldDefinition(field: GraphQLField<any, any>, details?: { objectType: GraphQLObjectType }, directive?: DirectiveNode) {
        const original = field.resolve;
        field.resolve = (parent: any, args: any, ctx: any, infos: any) => {
            return new Promise((resolve, reject) => {
                const currentUser = ctx.req.user;
                console.log('roles (' + (details && details.objectType ? details.objectType.name + '.' : '') + field.name + '): ', ctx.req.user)
                passport.authenticate('jwt', { session: false })(ctx.req, ctx.res, () => {
                    ctx.req.user = currentUser || ctx.req.user;
                    console.log('roles AFTER (' + (details && details.objectType ? details.objectType.name + '.' : '') + field.name + '): ', ctx.req.user)
                    const forArg = directive.arguments.find(arg => arg.name.value === 'name');
                    const forArgValues = (forArg.value as any).values.map(v => v && v.value);
                    if (ctx.req.user.roles.some(role => (console.log('forRole: ', role), forArgValues.includes(role.name)))) {
                        resolve(original.apply(this, [parent, args, ctx, infos]));
                    } else {
                        ctx.res.status(401);
                        reject(new Error('Not authorized: ' + (details && details.objectType ? details.objectType.name + '.' : '') + field.name));
                    }
                });
            });
        };
    }
}

export class SelfDirective extends SchemaDirectiveVisitor {
    _wrappedFields = {};
    _name = 'self';
    visitObject(objectType: GraphQLObjectType) {/*
        const thisDirective = objectType.astNode.directives.find(directive => directive.name.value === this._name);
        const forArgValues = ['all'];
        directiveRegister.register(this._name, objectType, forArgValues, this);
        const fields = objectType.getFields();
        Object.keys(fields).forEach(fieldName => this._visitFieldDefinition(fields[fieldName], undefined, thisDirective));*/
    }
    _visitFieldDefinition(field: GraphQLField<any, any>, details?: { objectType: GraphQLObjectType }, directive?: DirectiveNode) {

    }
}

export class OwnerDirective extends SchemaDirectiveVisitor {
    _wrappedFields = {};
    _name = 'owner';
    visitObject(objectType: GraphQLObjectType) {
        const thisDirective = objectType.astNode.directives.find(directive => directive.name.value === this._name);
        const forArg = thisDirective.arguments.find(arg => arg.name.value === 'for');
        const forArgValues = (forArg.value as any).values.map(v => v && v.value);
        directiveRegister.register(this._name, objectType, forArgValues, this);
    }
    visitFieldDefinition(field: GraphQLField<any, any>, details?: { objectType: GraphQLObjectType }, directive?: DirectiveNode) {
        if (['Create', 'Update', 'Delete'].some(action => field.name.startsWith(action))) {
            const original = field.resolve;
            const thisName = field.name.replace('Create', '').replace('Update', '').replace('Delete', '');
            field.resolve = (parent: any, args: any, ctx: any, infos: any) => {
                const currentUser = ctx.req.user;
                return new Promise((resolve, reject) => {
                    passport.authenticate('jwt', { session: false })(ctx.req, ctx.res, () => {
                        ctx.req.user = currentUser || ctx.req.user;
                        const exceptArg = directive.arguments.find(arg => arg.name.value === 'except');
                        const exceptArgValues = (exceptArg.value as any).values.map(v => v && v.value);
                        if (ctx.req.user.roles.some(role => exceptArgValues.includes(role.name))) {
                            resolve(original.apply(this, [parent, args, ctx, infos]));
                            return;
                        }
                        const id = args.id;
                        if (!id) {
                            original.apply(this, [parent, args, ctx, infos]).then(originalResult => {
                                const driver = ctx.driver;
                                const session = driver.session();
                                const closeSession = () => session.close();
                                const query = `
                                    MATCH (n: ${thisName} { id: "${id}" })<-[:OWN]-(u: User)
                                    RETURN u { .id } as ownerId
                                `;
                                closeSession();
                                console.log('originalResult: ', originalResult);
                                resolve(originalResult);
                            }, error => {
                                ctx.res.status(500);
                                reject({ message: `Something went wrong`, error });
                            });
                        } else {
                            const driver = ctx.driver;
                            const session = driver.session();
                            const closeSession = () => session.close();
                            const query = `
                                MATCH (n: ${thisName} { id: "${id}" })<-[:OWN]-(u: User)
                                RETURN u { .id } as ownerId
                            `;
                            session.run(query).then(({ records: { 0: result } }) => {
                                const ownerId = result && result.get('ownerId');
                                if (ownerId !== ctx.req.user.id) {
                                    ctx.res.status(401);
                                    reject({ message: `Not authorized` });
                                } else {
                                    ctx.req.user.roles.push({ name: 'owner' });
                                    resolve(original.apply(this, [parent, args, ctx, infos]));
                                }
                            }, error => {
                                ctx.res.status(500);
                                reject({ message: `Something went wrong`, error });
                            }).finally(closeSession);
                        }
                    });
                });
            }
        } else if (['Add', 'Remove'].some(action => field.name.startsWith(action))) {
            const original = field.resolve;
            field.resolve = (parent: any, args: any, ctx: any, infos: any) => {
                const currentUser = ctx.req.user;
                return new Promise((resolve, reject) => {
                    passport.authenticate('jwt', { session: false })(ctx.req, ctx.res, () => {
                        ctx.req.user = currentUser || ctx.req.user;
                        const exceptArg = directive.arguments.find(arg => arg.name.value === 'except');
                        const exceptArgValues = (exceptArg.value as any).values.map(v => v && v.value);
                        if (ctx.req.user.roles.some(role => exceptArgValues.includes(role.name))) {
                            resolve(original.apply(this, [parent, args, ctx, infos]));
                            return;
                        }
                        resolve(original.apply(this, [parent, args, ctx, infos]));
                    });
                });
            }
        } else {
            const original = field.resolve;
            field.resolve = (parent: any, args: any, ctx: any, infos: any) => {
                const currentUser = ctx.req.user;
                return new Promise((resolve, reject) => {
                    passport.authenticate('jwt', { session: false })(ctx.req, ctx.res, () => {
                        ctx.req.user = currentUser || ctx.req.user;
                        const exceptArg = directive.arguments.find(arg => arg.name.value === 'except');
                        const exceptArgValues = (exceptArg.value as any).values.map(v => v && v.value);
                        if (ctx.req.user.roles.some(role => exceptArgValues.includes(role.name))) {
                            resolve(original.apply(this, [parent, args, ctx, infos]));
                            return;
                        }
                        ctx.req.user.roles.push({ name: 'owner' });
                        original.apply(this, [parent, args, ctx, infos]).then(results => {
                            if (!results.some(result => !!result.id && !!result.owner && !!result.owner.User && !!result.owner.User.id)) {
                                ctx.res.status(401);
                                reject({ message: `Owned resources must contain an id and an owner User id` });
                            } else {
                                ctx.req.user.roles.forEach(r => console.log('role: ', r))
                                resolve(results.filter(result => result.owner.User.id === ctx.req.user.id));
                            }
                        });
                    });
                });
            }
        }
    }
}

export const schemaDirectives = {
    auth: AuthDirective,
    admin: AdminDirective,
    hasRole: HasRoleDirective,
    self: SelfDirective,
    owner: OwnerDirective,
};
