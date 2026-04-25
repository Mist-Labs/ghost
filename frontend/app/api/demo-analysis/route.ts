import { loadActiveProtocols } from "@/lib/protocols";
import { runProtocolAnalysis } from "@/lib/server/analysis";

type RequestPayload = {
  protocolId?: string;
};

export async function POST(request: Request) {
  const body = (await request.json().catch(() => ({}))) as RequestPayload;
  const activeProtocols = await loadActiveProtocols();
  const defaultProtocolId = activeProtocols[0]?.id;
  const protocolId = body.protocolId || defaultProtocolId;

  if (!protocolId) {
    return Response.json({ error: "No demo protocol is configured." }, { status: 404 });
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const push = async (payload: unknown) => {
        controller.enqueue(encoder.encode(`${JSON.stringify(payload)}\n`));
      };

      try {
        await runProtocolAnalysis(protocolId, push);
      } catch (error) {
        await push({
          type: "error",
          message:
            error instanceof Error ? error.message : "Unexpected demo error",
        });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-cache, no-transform",
    },
  });
}
