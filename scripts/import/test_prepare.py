from pathlib import Path
import stat
import tempfile
import unittest

from prepare import main, prepare_result


class PrepareTests(unittest.TestCase):
    def test_stable_source_id_survives_line_changes_and_keeps_sender_separate(self):
        transcript = 'May 17, 2026  5:29:42 PM\nMe\n"A fictional line" - Rowan\n'
        padded = '\n' + transcript
        first = prepare_result(transcript, 'Example Chat', 'Avery')
        second = prepare_result(padded, 'Example Chat', 'Avery')
        candidate = first['candidates'][0]
        self.assertEqual(candidate['source_id'], second['candidates'][0]['source_id'])
        self.assertEqual(candidate['source_chat'], 'Example Chat')
        self.assertEqual(candidate['source_sender'], 'Avery')
        self.assertEqual(candidate['author'], 'Rowan')

    def test_aliases_change_display_without_changing_source_id(self):
        transcript = 'May 17, 2026  5:29:42 PM\nTaylor\n"A fictional line" - Rowan\n'
        plain = prepare_result(transcript, 'Example Chat', 'Avery')
        aliased = prepare_result(transcript, 'Example Chat', 'Avery', {'Taylor': 'T.', 'Rowan': 'R.'})
        self.assertEqual(plain['candidates'][0]['source_id'], aliased['candidates'][0]['source_id'])
        self.assertEqual(aliased['candidates'][0]['source_sender'], 'T.')
        self.assertEqual(aliased['candidates'][0]['author'], 'R.')

    def test_identity_ignores_reaction_appendage_and_sender_display_name(self):
        plain = 'May 17, 2026  5:29:42 PM\nMe\n"A fictional line" - Rowan\n'
        reaction = (plain + 'Tapbacks:\n    Rowan liked this message\n'
                    'This message responded to an earlier message.\n')
        first = prepare_result(plain, 'Example Chat', 'Avery')
        second = prepare_result(reaction, 'Example Chat', 'Morgan')
        self.assertEqual(first['candidates'][0]['source_id'], second['candidates'][0]['source_id'])
        self.assertEqual(second['candidates'][0]['source_sender'], 'Morgan')

    def test_joint_attribution_resolves_me_to_sender_and_aliases_each_name(self):
        transcript = 'May 17, 2026  5:29:42 PM\nTaylor\n"A fictional line" - me & row\n'
        candidate = prepare_result(transcript, 'Example Chat', 'Avery',
                                   {'Taylor': 'T.', 'Row': 'Rowan'})['candidates'][0]
        self.assertEqual(candidate['author'], 'T. & Rowan')
        self.assertEqual(candidate['source_sender'], 'T.')
        self.assertEqual(candidate['text'], 'A fictional line')

    def test_relative_speakers_do_not_merge_different_people(self):
        transcript = ('May 17, 2026  5:29:42 PM\nTaylor\n"One line" - me & Rowan\n'
                      'May 17, 2026  5:30:42 PM\nMe\n"One line" - me & Rowan\n')
        candidates = prepare_result(transcript, 'Example Chat', 'Avery')['candidates']
        self.assertEqual([row['author'] for row in candidates], ['Taylor & Rowan', 'Avery & Rowan'])

    def test_aliases_rebuild_dialogue_labels_and_corrections_are_context(self):
        transcript = (
            'May 17, 2026  5:29:42 PM\nTaylor\n"One" - Rowan\n"Two" - Morgan\n'
            '    May 17, 2026  5:29:43 PM\n    Taylor\n    "Three" - correction\n'
        )
        candidate = prepare_result(transcript, 'Example Chat', 'Avery',
                                   {'Taylor': 'T.', 'Rowan': 'R.', 'Morgan': 'M.'})['candidates'][0]
        self.assertEqual(candidate['text'], 'R.: “One”\nM.: “Two”')
        self.assertEqual(candidate['author'], 'R. & M.')
        self.assertEqual(candidate['context'], 'Correction from T.: Three')

    def test_main_refuses_existing_output_and_writes_private_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            transcript = folder / 'fictional.txt'
            transcript.write_text('May 17, 2026  5:29:42 PM\nAvery\n"A fictional line" - Rowan\n')
            output = folder / 'review'
            args = [str(transcript), '--chat', 'Example Chat', '--self-name', 'Avery', '--output', str(output)]
            main(args)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / 'quote-review.html').stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((output / 'quote-review-data.json').stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                main(args)


if __name__ == '__main__':
    unittest.main()
