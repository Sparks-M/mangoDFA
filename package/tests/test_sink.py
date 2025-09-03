from unittest import mock, TestCase

from angr.sim_type import SimTypeFunction, SimTypeInt

from argument_resolver.external_function import VULN_TYPES, Sink
from argument_resolver.external_function.sink.sink_lists import STRING_FORMAT_SINKS


class TestSink(TestCase):
    MOCK_LIBRARIES = {
        "a_sink": SimTypeFunction([SimTypeInt()], SimTypeInt(), arg_names=["key"]),
    }

    @mock.patch(
        "argument_resolver.external_function.CUSTOM_DECLS",
        MOCK_LIBRARIES,
    )
    def test_expose_list_of_command_injection_sinks(self):
        for f in VULN_TYPES["cmdi"]:
            self.assertEqual(type(f), Sink)

    @mock.patch(
        "argument_resolver.external_function.CUSTOM_DECLS",
        MOCK_LIBRARIES,
    )
    def test_a_sink_has_a_dictionary_of_vulnerable_parameters_specifying_their_positions_and_type(
        self,
    ):
        sink = Sink("a_sink", [1])
        vulnerable_parameters = [1]

        self.assertListEqual(sink.vulnerable_parameters, vulnerable_parameters)

    def test_string_format_sinks_have_correct_vulnerable_parameters(self):
        """Test that sprintf and snprintf have correct vulnerable parameter indices after patch"""
        sprintf_sink = None
        snprintf_sink = None
        
        for sink in STRING_FORMAT_SINKS:
            if sink.name == "sprintf":
                sprintf_sink = sink
            elif sink.name == "snprintf":
                snprintf_sink = sink
        
        self.assertIsNotNone(sprintf_sink, "sprintf sink should exist in STRING_FORMAT_SINKS")
        self.assertIsNotNone(snprintf_sink, "snprintf sink should exist in STRING_FORMAT_SINKS")
        
        # After the patch, both should have vulnerable_parameters=[1]
        self.assertEqual(sprintf_sink.vulnerable_parameters, [1], 
                        "sprintf should have vulnerable_parameters=[1] after patch")
        self.assertEqual(snprintf_sink.vulnerable_parameters, [1], 
                        "snprintf should have vulnerable_parameters=[1] after patch")
