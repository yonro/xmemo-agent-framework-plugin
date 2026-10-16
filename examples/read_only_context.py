"""Community submission draft: opt-in read-only context, no model or capture."""
import asyncio
import os
from xmemo_agent_framework import Connection, Policy, Provider, ReadRoute
from xmemo_agent_framework.maf import XMemoContextProvider


def create_context_provider():
    """The host owns the connection and closes it after the agent session."""
    connection = Connection(os.environ['XMEMO_URL'], os.environ['XMEMO_API_KEY'])
    provider = Provider(
        connection,
        Policy(recall_enabled=True, route=ReadRoute.RECALL,
               max_items=8, max_tokens=2000),
        agent_id='community-sample', agent_instance_id='local-instance',
    )
    return connection, XMemoContextProvider(provider)


async def main():
    connection, context_provider = create_context_provider()
    try:
        # This standalone demonstration uses the same core read path. To attach
        # it to MAF, pass context_provider to Agent(context_providers=[...]).
        result = await context_provider.provider.before_run(
            os.environ.get('XMEMO_QUERY', 'Resume the current project'),
            session_id='community-sample-session',
        )
        print(f'outcome={result.audit.outcome}; items={len(result.items)}')
    finally:
        await connection.aclose()


if __name__ == '__main__':
    asyncio.run(main())
