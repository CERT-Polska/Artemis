from test.base import ArtemisModuleTestCase

from karton.core import Task

from artemis.binds import Service, TaskStatus, TaskType
from artemis.modules.graphql_scanner import GraphQLScanner


class GraphQLScannerTest(ArtemisModuleTestCase):
    # The reason for ignoring mypy error is https://github.com/CERT-Polska/karton/issues/201
    karton_class = GraphQLScanner  # type: ignore

    def test_detects_introspection_and_graphiql(self) -> None:
        """
        The test-graphql-server container exposes /graphql with:
        - POST: introspection enabled (returns full __schema response)
        - GET: GraphiQL HTML debug interface
        - Field suggestions enabled (returns 'Did you mean...?' on misspelled fields)
        """
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-graphql-server",
                "port": 5000,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.INTERESTING)

        data = call.kwargs["data"]
        self.assertIn("graphql_endpoint", data)
        self.assertIn("introspection", data)
        self.assertIn("debug_interface", data)
        self.assertIn("field_suggestions", data)

        introspection = data["introspection"]
        self.assertGreater(introspection["num_types_exposed"], 0)
        self.assertEqual(introspection["query_type"], "Query")

        debug = data["debug_interface"]
        self.assertIn("GraphiQL", debug["interface_type"])

    def test_no_graphql_endpoint(self) -> None:
        """
        test-nginx has no GraphQL endpoint — should produce TaskStatus.OK
        with an empty data dict.
        """
        task = Task(
            {"type": TaskType.SERVICE.value, "service": Service.HTTP.value},
            payload={
                "host": "test-nginx",
                "port": 80,
            },
        )

        self.run_task(task)
        (call,) = self.mock_db.save_task_result.call_args_list
        self.assertEqual(call.kwargs["status"], TaskStatus.OK)
        self.assertEqual(call.kwargs["data"], {})
