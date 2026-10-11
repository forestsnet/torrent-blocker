"""Юнит-тесты различения веер-ложняка (2.3.0). Модуль импортируется из файла с дефисами в
имени; импорт-гард в самом скрипте (parse_args([]) при __name__ != '__main__') даёт дефолты.
Чистые функции тестируем с подставным резолвером — без сети и без ноды."""

import importlib.util
import pathlib
import unittest

_P = pathlib.Path(__file__).resolve().parent.parent / 'fsnt-torrent-blocker.py'
_spec = importlib.util.spec_from_file_location('ftb', _P)
assert _spec and _spec.loader
ftb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ftb)


class HostVerdict(unittest.TestCase):
    def setUp(self):
        self.nm = ftb.NetMatch([])

    def test_hoster_ptr_is_dc(self):
        for ptr, ip in [
            ('static.201.191.168.204.clients.your-server.de', '204.168.191.201'),  # Hetzner
            ('vmi2604272.contaboserver.net', '95.111.248.57'),                      # Contabo
            ('118.152.65.34.bc.googleusercontent.com', '34.65.152.118'),            # GCP
            ('v2202505271268337632.powersrv.de', '152.53.254.119'),                 # netcup/powersrv
        ]:
            self.assertEqual(ftb.host_verdict(ptr, ip, self.nm), 'dc', ptr)

    def test_residential_ptr_is_res(self):
        for ptr in ['broadband-46-31-31-151.seven-sky.net',
                    'dynamic-x.dsl.example.ru',
                    'pool-72-1.cable.example.net']:
            self.assertEqual(ftb.host_verdict(ptr, '1.2.3.4', self.nm), 'res', ptr)

    def test_no_ptr_is_unknown(self):
        self.assertEqual(ftb.host_verdict('', '203.0.113.9', self.nm), 'unknown')

    def test_dc_nets_beats_missing_ptr(self):
        nm = ftb.NetMatch(['203.0.113.0/24'])
        self.assertEqual(ftb.host_verdict('', '203.0.113.9', nm), 'dc')


class ClassifyHosts(unittest.TestCase):
    def test_counts_with_fake_resolver(self):
        ptr = {
            '204.168.191.201': 'static.x.clients.your-server.de',
            '95.111.248.57': 'vmi1.contaboserver.net',
            '34.65.152.118': 'x.bc.googleusercontent.com',
            '46.31.31.151': 'broadband-46-31-31-151.seven-sky.net',
            '198.51.100.7': '',   # нет PTR -> unknown
        }
        dc, res, unk = ftb.classify_hosts(list(ptr), resolve=lambda ip: ptr.get(ip, ''),
                                          dc_nets=ftb.NetMatch([]), deadline=5.0)
        self.assertEqual((dc, res, unk), (3, 1, 1))


class DecideVeer(unittest.TestCase):
    def test_tiering_off_always_bans(self):
        self.assertEqual(ftb.decide_veer(10, 0, 0, False, 1, tiering=False), 'ban')

    def test_btguard_confirms_ban(self):
        self.assertEqual(ftb.decide_veer(0, 0, 0, True, 1), 'ban')

    def test_datacenter_swarm_suppressed(self):
        # 13 dc / 1 res / 1 unknown: coverage .93, доля dc .93 >= .8
        self.assertEqual(ftb.decide_veer(13, 1, 1, False, 1), 'suppress')

    def test_residential_first_trip_is_suspect(self):
        self.assertEqual(ftb.decide_veer(1, 20, 2, False, 1), 'suspect')

    def test_residential_repeat_bans(self):
        self.assertEqual(ftb.decide_veer(1, 20, 2, False, 2), 'ban')

    def test_low_coverage_not_suppressed(self):
        # много unknown -> coverage < .6 -> не подавляем (в suspect, не ложный разбан)
        self.assertEqual(ftb.decide_veer(5, 0, 20, False, 1), 'suspect')


if __name__ == '__main__':
    unittest.main()
