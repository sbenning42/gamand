import { SchemaDirectiveVisitor } from "graphql-tools";
import { GraphQLObjectType, GraphQLField } from "graphql";

import passport from 'passport';

export class Owner extends SchemaDirectiveVisitor {
    visitObject(...args: any[]) {
        console.log('In Owner visitObject.');
    }
    visitFieldDefinition(...args: any[]) {
        console.log('In Owner visitFieldDefinition.');
    }
}

export class Admin extends SchemaDirectiveVisitor {
    visitObject(type) {
        this.ensureFieldsWrapped(type);
    }
    // Visitor methods for nested types like fields and arguments
    // also receive a details object that provides information about
    // the parent and grandparent types.
    visitFieldDefinition(field, details) {
        this.ensureFieldsWrapped(details.objectType);
    }
    ensureFieldsWrapped(objectType) {
        // Mark the GraphQLObjectType object to avoid re-wrapping:
        if (objectType._authFieldsWrapped) {
            return;
        }
        objectType._authFieldsWrapped = true;
        const fields = objectType.getFields();
        Object.keys(fields).forEach(fieldName => {
            const field = fields[fieldName];
            const original = field.resolve;
            field.resolve = (parent: any, args: any, ctx: any, infos: any) => {
                const authenticated = ctx.auth.services.isAuthenticated(ctx.req);
                const user = ctx.auth.services.getUser(ctx.req);
                const roles = ctx.auth.services.getRoles(ctx.req);
                if (!authenticated) {
                    ctx.res.status(401);
                    throw new Error('Not authenticated');
                } else if (!roles.some(role => role.name === 'admin')) {
                    ctx.res.status(401);
                    throw new Error('Not GRANTED');
                }
                return original.apply(this, [parent, args, ctx, infos]);
            };
        });
    }
}

export class Authenticated extends SchemaDirectiveVisitor {
    visitObject(type) {
        this.ensureFieldsWrapped(type);
    }
    // Visitor methods for nested types like fields and arguments
    // also receive a details object that provides information about
    // the parent and grandparent types.
    visitFieldDefinition(field, details) {
        this.ensureFieldsWrapped(details.objectType);
    }
    ensureFieldsWrapped(objectType) {
        // Mark the GraphQLObjectType object to avoid re-wrapping:
        if (objectType._authFieldsWrapped) {
            return;
        }
        objectType._authFieldsWrapped = true;
        const fields = objectType.getFields();
        Object.keys(fields).forEach(fieldName => {
            const field = fields[fieldName];
            const original = field.resolve;
            field.resolve = (parent: any, args: any, ctx: any, infos: any) => {
                if (!ctx.auth.services.isAuthenticated(ctx.req)) {
                    ctx.res.status(401);
                    throw new Error('Not authenticated');
                }
                return original.apply(this, [parent, args, ctx, infos]);
            };
        });
    }
}

export class AuthDirective extends SchemaDirectiveVisitor {
    _wrappedFields = {};
    visitObject(objectType: GraphQLObjectType) {
        console.log('AuthDirective@visitObject: ', objectType.name);
        const fields = objectType.getFields();
        Object.keys(fields).forEach(fieldName => this.visitFieldDefinition(fields[fieldName]));
    }
    visitFieldDefinition(field: GraphQLField<any, any>, details?: { objectType: GraphQLObjectType }) {
        const relativeName = details ? `${details.objectType.name}.${field.name}` : field.name;
        console.log('AuthDirective@visitFieldDefinition: ', relativeName);
        if (this._wrappedFields[relativeName]) {
            return;
        }
        this._wrappedFields[relativeName] = true;
        const original = field.resolve;
        field.resolve = (parent: any, args: any, ctx: any, infos: any) => {
            return new Promise((resolve, reject) => {
                passport.authenticate('jwt', { session: false })(ctx.req, ctx.res, () => {
                    console.log(`AuthDirective@visitFieldDefinition.${relativeName}@resolve: `, ctx.req.user);
                    resolve(original.apply(this, [parent, args, ctx, infos]));
                });
            });
        };
    }
}

export const schemaDirectives = {
    auth: AuthDirective
};
