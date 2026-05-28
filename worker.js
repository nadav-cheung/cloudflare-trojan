export default {
    async fetch(request, env, ctx) {
        return new Response("OK");
    },

    async scheduled(controller, env, ctx) {}
};
