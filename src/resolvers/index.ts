export const resolvers = {
    Query: {
        User: (parent: any, args: any, ctx: any, infos: any) => {
            return ctx.neo4jgraphql(parent, args, ctx, infos);
        }
    },
    Mutation: {
    },
};
