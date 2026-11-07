"""Юнит-тесты allow-листа (2.4.0). Проверяем разбор файла, совпадение по адресу, сети и
userId и перечитывание по mtime. Импорт как в test_veer_tiering: имя файла с дефисами."""

import importlib.util
import os
import pathlib
import tempfile
import time
import unittest

_P = pathlib.Path(__file__).resolve().parent.parent / 'fsnt-torrent-blocker.py'
_spec = importlib.util.spec_from_file_location('ftb', _P)
assert _spec and _spec.loader
ftb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ftb)


class SplitEntries(unittest.TestCase):
    def test_addresses_nets_and_users(self):
        nets, users = ftb.AllowList.split_entries([
            '87.242.95.93', '10.0.0.0/8', '2a14:a087::/48', 'user:224780', '86515',
        ])
        self.assertEqual(nets, ['87.242.95.93', '10.0.0.0/8', '2a14:a087::/48'])
        self.assertEqual(users, {'224780', '86515'})

    def test_comments_and_blanks_dropped(self):
        nets, users = ftb.AllowList.split_entries([
            '', '   ', '# целиком комментарий', '5.178.85.11  # релей Selectel',
            'user:12  # он же', None,
        ])
        self.assertEqual(nets, ['5.178.85.11'])
        self.assertEqual(users, {'12'})

    def test_garbage_goes_to_nets_and_is_ignored_there(self):
        # NetMatch молча отбрасывает нераспознанное — опечатка в файле не валит демона
        nets, _ = ftb.AllowList.split_entries(['не-адрес'])
        self.assertEqual(nets, ['не-адрес'])
        self.assertNotIn('87.242.95.93', ftb.NetMatch(nets))


class Matching(unittest.TestCase):
    def setUp(self):
        self.al = ftb.AllowList('/nonexistent/allow.list',
                                inline_src='87.242.95.93, 10.8.0.0/24',
                                inline_users='224780')

    def test_plain_address(self):
        self.assertEqual(self.al.allows('1', '87.242.95.93'), 'адрес')

    def test_inside_cidr(self):
        self.assertEqual(self.al.allows('1', '10.8.0.77'), 'адрес')

    def test_outside_cidr(self):
        self.assertIsNone(self.al.allows('1', '10.9.0.77'))

    def test_user_id_matches_as_string_or_int(self):
        self.assertEqual(self.al.allows('224780', '1.2.3.4'), 'userId')
        self.assertEqual(self.al.allows(224780, '1.2.3.4'), 'userId')

    def test_unknown_client_not_allowed(self):
        self.assertIsNone(self.al.allows('999', '203.0.113.9'))

    def test_missing_file_leaves_inline_in_force(self):
        self.assertEqual(self.al.describe(), '2 адресов/сетей, 1 userId')
        self.assertFalse(self.al.reload())      # файла нет — нечего перечитывать


class ReloadsByMtime(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(prefix='ftb-allow-')
        os.close(fd)
        self.addCleanup(os.unlink, self.path)
        self._write('5.178.85.11\n')
        self.al = ftb.AllowList(self.path)

    def _write(self, text):
        with open(self.path, 'w', encoding='utf-8') as f:
            f.write(text)

    def test_initial_read(self):
        self.assertEqual(self.al.allows('1', '5.178.85.11'), 'адрес')
        self.assertIsNone(self.al.allows('1', '188.225.57.18'))

    def test_unchanged_file_is_not_reparsed(self):
        self.assertFalse(self.al.reload())

    def test_picks_up_new_entries(self):
        time.sleep(0.01)
        self._write('5.178.85.11\n188.225.57.18\nuser:42\n')
        self.assertTrue(self.al.reload())
        self.assertEqual(self.al.allows('1', '188.225.57.18'), 'адрес')
        self.assertEqual(self.al.allows('42', '1.2.3.4'), 'userId')

    def test_emptied_file_clears_list(self):
        time.sleep(0.01)
        self._write('')
        self.assertTrue(self.al.reload())
        self.assertIsNone(self.al.allows('1', '5.178.85.11'))


if __name__ == '__main__':
    unittest.main()
