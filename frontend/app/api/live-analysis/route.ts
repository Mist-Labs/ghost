import { getOptionalSessionAccount } from "@/lib/server/auth";
import { loadActiveProtocols } from "@/lib/protocols";
import { runProtocolAnalysisForProtocol } from "@/lib/server/analysis";
import { getOperatorProtocolByKey } from "@/lib/server/operator-protocols";

type RequestPayload = {
  protocolId?: string;
};

export async function POST(request: Request) {
  const account = await getOptionalSessionAccount();
  if (!account) {
    return Response.json({ error: "Authentication required." }, { status: 401 });
  }

  const body = (await request.json()) as RequestPayload;
  if (!body.protocolId) {
    return Response.json({ error: "protocolId is required" }, { status: 400 });
  }

  const protocol =
    (await getOperatorProtocolByKey(account.id, body.protocolId)) ??
    (await loadActiveProtocols()).find((entry) => entry.id === body.protocolId) ??
    null;
  if (!protocol) {
    return Response.json({ error: "Protocol not found." }, { status: 404 });
  }

  const encoder = new TextEncoder();

  const stream = new ReadableStream({
    async start(controller) {
      const push = async (payload: unknown) => {
        controller.enqueue(encoder.encode(`${JSON.stringify(payload)}\n`));
      };

      try {
        await runProtocolAnalysisForProtocol(protocol, push);
      } catch (error) {
        await push({
          type: "error",
          message:
            error instanceof Error ? error.message : "Unexpected analysis error",
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
