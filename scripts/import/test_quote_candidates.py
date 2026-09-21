import unittest

from quote_candidates import _messages, parse_export


class QuoteCandidateTests(unittest.TestCase):
    def test_quote_only_parent_with_only_nested_reply_at_end_is_safe(self):
        result = parse_export('May 17, 2026  5:29:42 PM\nAlice\n"Question?"\n'
                              '    May 17, 2026  5:30:42 PM\n    Bob\n    A reply\n')
        self.assertEqual(result['candidates'], [])

    def test_top_level_correction_before_linked_render_attaches_after_parse(self):
        result = parse_export('May 17, 2026  5:30:42 PM\nBob\n"Changed" - correction\n'
                              'May 17, 2026  5:29:42 PM\nAlice\n"Original" - Bob\n'
                              '    May 17, 2026  5:30:42 PM\n    Bob\n    "Changed" - correction\n')
        self.assertEqual(len(result['candidates']), 1)
        self.assertEqual(result['candidates'][0]['corrections'][0]['parent'], 4)

    def test_question_without_attribution_is_not_lost_or_assigned_to_answerer(self):
        candidate = parse_export('May 17, 2026  5:29:42 PM\nAlice\n"Question?"\n"Answer" - Bob\n')["candidates"][0]
        self.assertEqual([p["text"] for p in candidate["parts"]], ["Question?", "Answer"])
        self.assertEqual([p["author"] for p in candidate["parts"]], ["", "Bob"])

    def test_dedupe_preserves_different_dialogue_speakers(self):
        result = parse_export('May 17, 2026  5:29:42 PM\nAlice\n"One" - Bob\n"Two" - Dana\nMay 18, 2026  5:29:42 PM\nAlice\n"One" - Dana\n"Two" - Bob\n')
        self.assertEqual(len(result["candidates"]), 2)

    def test_empty_quote_and_inline_chatter_are_not_quotes(self):
        result = parse_export('May 17, 2026  5:29:42 PM\nBob\n"" - Bob\nOrdinary "inline" chatter\n')
        self.assertEqual(result["candidates"], [])

    def test_multiline_self_quote_and_receipt(self):
        candidate = parse_export('May 17, 2026  5:29:42 PM (Read by somebody)\nBob\n“First\nsecond” — Bob\n')["candidates"][0]
        self.assertEqual(candidate["text"], "First\nsecond")
        self.assertEqual(candidate["author"], "Bob")
        self.assertEqual(candidate["source_timestamp"], 'May 17, 2026  5:29:42 PM')

    def test_shared_trailing_attribution_keeps_the_entire_dialogue(self):
        result = parse_export(
            'May 17, 2026  5:29:42 PM\nAlice\n"A"\n"B"\n"C"\n- guess who\n'
        )

        candidate = result["candidates"][0]
        self.assertEqual([p["text"] for p in candidate["parts"]], ["A", "B", "C"])
        self.assertEqual(candidate["author"], "")
        self.assertTrue(candidate["needs_review"])
        self.assertEqual(candidate["parts"], [
            {"text": "A", "author": "", "source_line": 3},
            {"text": "B", "author": "", "source_line": 4},
            {"text": "C", "author": "", "source_line": 5},
        ])
        self.assertEqual(candidate["raw_body"], '"A"\n"B"\n"C"\n- guess who')

    def test_merges_attributed_fragments_from_one_message_in_order(self):
        result = parse_export(
            'May 18, 2026  5:29:42 PM\nAlice\n"One" - Bob\n"Two" - Dana\n'
        )

        candidate = result["candidates"][0]
        self.assertEqual(candidate["text"], 'Bob: “One”\nDana: “Two”')
        self.assertEqual(candidate["author"], "Bob & Dana")
        self.assertEqual(candidate["parts"], [
            {"text": "One", "author": "Bob", "source_line": 3},
            {"text": "Two", "author": "Dana", "source_line": 4},
        ])
        self.assertEqual(candidate["source_message_line"], 1)
        self.assertEqual(candidate["source_line"], 3)

    def test_deduplication_retains_all_requested_occurrence_identity(self):
        result = parse_export(
            'May 19, 2026  5:29:42 PM\nAlice\n"Words" - Bob\n'
            'May 20, 2026  5:29:42 PM\nDana\n"Words" - Bob\n'
        )

        candidate = result["candidates"][0]
        self.assertEqual(candidate["count"], 2)
        self.assertEqual(candidate["source_lines"], [3, 6])
        self.assertEqual(candidate["occurrences"], [
            {"source_message_line": 1, "source_line": 3,
             "source_timestamp": "May 19, 2026  5:29:42 PM"},
            {"source_message_line": 4, "source_line": 6,
             "source_timestamp": "May 20, 2026  5:29:42 PM"},
        ])

    def test_does_not_cross_nested_message_or_tapback_boundaries(self):
        result = parse_export(
            'May 21, 2026  5:29:42 PM\nAlice\n"Outer" - Bob\nTapbacks:\n'
            '    "Reaction" - Reactor\n'
            '    May 22, 2026  5:29:42 PM\n    Dana\n"Nested" - Erin\n'
        )

        self.assertEqual(result["messages"], 2)
        self.assertEqual([(item["text"], item["author"]) for item in result["candidates"]],
                         [("Outer", "Bob"), ("Nested", "Erin")])

    def test_top_level_attribution_message_completes_quote_only_message(self):
        result = parse_export(
            'May 23, 2026  5:29:42 PM\nAlice\n"Full quote"\n'
            'May 23, 2026  5:30:02 PM\nAlice\n- Bob\n'
        )
        candidate = result["candidates"][0]
        self.assertEqual(candidate["parts"][0]["author"], "Bob")
        self.assertEqual(candidate["attribution_message_line"], 4)

    def test_nested_reply_correction_is_metadata_and_duplicate_is_ignored(self):
        text = (
            'May 24, 2026  5:29:42 PM\nAlice\n"Original" - Bob\n'
            '    May 24, 2026  5:30:02 PM\n    Alice\n    "we would still be" - correction\n'
            'May 24, 2026  5:30:02 PM\nAlice\n"we would still be" - correction\n'
            'This message responded to an earlier message.\n'
        )
        result = parse_export(text)
        self.assertEqual(len(result["candidates"]), 1)
        candidate = result["candidates"][0]
        self.assertEqual(candidate["text"], "Original")
        self.assertEqual(candidate["corrections"], [{
            "text": "we would still be", "sender": "Alice",
            "source_message_line": 4, "source_line": 6, "parent": 1,
        }])
        self.assertEqual(list(_messages(text))[1]["parent_source_message_line"], 1)

    def test_split_attribution_skips_nested_correction_and_keeps_linked_source(self):
        result = parse_export(
            'May 24, 2026  5:29:42 PM\nAlice\n"Original"\n'
            '    May 24, 2026  5:29:43 PM\n    Alice\n    "we would still be" - correction\n'
            'May 24, 2026  5:29:43 PM\nAlice\n- Bob\n'
            'May 24, 2026  5:29:43 PM\nAlice\n"we would still be" - correction\n'
            'This message responded to an earlier message.\n'
        )
        candidate = result["candidates"][0]
        self.assertEqual(candidate["author"], "Bob")
        self.assertEqual(candidate["attribution_message_line"], 7)
        self.assertEqual(candidate["corrections"], [{
            "text": "we would still be", "sender": "Alice",
            "source_message_line": 4, "source_line": 6, "parent": 1,
        }])

    def test_attribution_neighbor_requires_same_sender_nearby_and_no_ordinary_text(self):
        cases = [
            ('May 25, 2026  5:29:42 PM\nAlice\n"Q"\nMay 25, 2026  5:30:02 PM\nDana\n- Bob\n'),
            ('May 25, 2026  5:29:42 PM\nAlice\n"Q"\nMay 25, 2026  5:31:02 PM\nAlice\n- Bob\n'),
            ('May 25, 2026  5:29:42 PM\nAlice\n"Q"\nMay 25, 2026  5:30:02 PM\nAlice\n- Bob\nordinary\n'),
        ]
        for text in cases:
            self.assertEqual(parse_export(text)["candidates"], [])

    def test_unlinked_correction_does_not_become_a_quote(self):
        result = parse_export(
            'May 26, 2026  5:29:42 PM\nAlice\n"Original" - Bob\n'
            'May 26, 2026  5:30:02 PM\nAlice\n"fragment" - correction\n'
        )
        self.assertEqual([(item["text"], item["author"]) for item in result["candidates"]],
                         [("Original", "Bob")])

    def test_ordinary_top_level_message_stops_attribution_lookup(self):
        result = parse_export(
            'May 26, 2026  5:29:42 PM\nAlice\n"Original"\n'
            'May 26, 2026  5:29:43 PM\nAlice\nordinary text\n'
            'May 26, 2026  5:29:44 PM\nAlice\n- Bob\n'
        )
        self.assertEqual(result["candidates"], [])

    def test_malformed_message_does_not_acquire_a_parent(self):
        messages = list(_messages('    May 27, 2026  5:29:42 PM\n    Alice\n    "Q" - Bob\n'))
        self.assertEqual(messages[0]["parent_source_message_line"], None)


if __name__ == "__main__":
    unittest.main()
