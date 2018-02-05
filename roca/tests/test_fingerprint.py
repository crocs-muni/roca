#!/usr/bin/env python
# -*- coding: utf-8 -*-

from roca.detect import RocaFingerprinter, flatten, drop_none, AutoJSONEncoder
import random
import base64
import unittest
import pkg_resources


__author__ = 'dusanklinec'


class FprintTest(unittest.TestCase):
    """Simple Fingerprint tests"""

    def __init__(self, *args, **kwargs):
        super(FprintTest, self).__init__(*args, **kwargs)
        self.inputs = []
        self.positive_samples = [
            'mod01.txt', 'mod02.txt', 'mod03.txt', 'mod08.txt', 'mod09.txt', 'key04.pgp',
            'cert04.pem', 'cert05.pem', 'ssh06.pub', 'pubkey03.pem', 'privkey05.pem', 'csr05.pem'
        ]

    def setUp(self):
        """
        Loads testing certs
        :return:
        """
        fls = pkg_resources.resource_listdir(__name__, 'data')
        fls = [x for x in fls if
               x.endswith('.pem') or
               x.endswith('.txt') or
               x.endswith('.pub') or
               x.endswith('.pgp') or
               x.endswith('.p7s')]

        for fname in fls:
            self.inputs.append((fname, self._get_res(fname)))

    def tearDown(self):
        """
        Cleanup
        :return:
        """

    def _get_res(self, name):
        """
        Loads resource
        :param name:
        :return:
        """
        resource_package = __name__
        resource_path = '/'.join(('data', name))
        return pkg_resources.resource_string(resource_package, resource_path)

    def test_primorial(self):
        """
        Simple primorial test
        :return:
        """
        fp = RocaFingerprinter()
        m, phi = fp.dlog_fprinter.primorial(167)

        self.assertEqual(m, 962947420735983927056946215901134429196419130606213075415963491270)
        self.assertEqual(phi, 103869096713434131141462689130396531045414801386011361280000000000)

    def fprint_subtest(self, fprinter):
        """
        Basic fingerprinter test
        :param fprinter:
        :return:
        """
        self.assertGreaterEqual(len(self.inputs), 19, 'Some inputs are missing')

        for fname, data in self.inputs:
            ret = drop_none(flatten(fprinter.process_file(data, fname)))
            self.assertGreaterEqual(len(ret), 1, 'At least one result expected')

            if fname.endswith('.txt'):
                self.assertEqual(len(ret), 1, 'Hex mod input epxected result count is 1, not %s' % len(ret))
                self.assertEqual('mod-hex', ret[0].type, 'File type detection failed')

            for sub in ret:
                self.assertIsNone(sub.error, 'Unexpected error with file %s : %s' % (fname, sub.error))
                self.assertEqual(fname, sub.fname, 'Filename mismatch')
                self.assertIsNotNone(sub.n, 'Modulus is empty')
                self.assertGreaterEqual(len(sub.n), 10, 'Modulus is too short')

                if fname in self.positive_samples:
                    self.assertTrue(sub.marked, 'False negative detection on fingerprinted modulus: %s' % fname)
                else:
                    self.assertFalse(sub.marked, 'False positive detection on non-fingerprinted modulus %s' % fname)

    def test_fprint_moduli(self):
        """
        Test fingerprints
        :return:
        """
        fprinter = RocaFingerprinter()
        fprinter.switch_fingerprint_method(True)
        self.assertEqual(fprinter.has_fingerprint, fprinter.has_fingerprint_moduli)
        self.fprint_subtest(fprinter)

    def test_fprint_dlog(self):
        """
        Test fingerprints - dlog method
        :return:
        """
        fprinter = RocaFingerprinter()
        fprinter.switch_fingerprint_method(False)
        self.assertEqual(fprinter.has_fingerprint, fprinter.has_fingerprint_dlog)
        self.fprint_subtest(fprinter)

    def test_fake_mods(self):
        """
        Fake modulus - positive by old method, negative by dlog method
        :return:
        """
        fprinter_moduli = RocaFingerprinter()
        fprinter_dlog = RocaFingerprinter()

        fprinter_moduli.switch_fingerprint_method(True)
        fprinter_dlog.switch_fingerprint_method(False)

        fake_mods = [
            72414128973967872688332736535017614208620368242015797102796086827882754006260204061799547004983731426777596445658889886861027045033760014948048067467947960318205453778973975867532910489227970143091184725760290172935872752222320334100097730483600892686353719855397381316384244147860260153198611313067061116317,
            138345973265163614694352477004469191286459111070564516299381495188624946671065451924677704628892476011773201612117597303315530745738015579159106259811204610647347662150159814774894784524366138220226431598991937057442020694466365850170057813627445465881816985939192840583168136876337135351417253708364245923133,
            60828061238058485055546209519792949600733446820687109700021551748017165461584398468231416589035982737511901116540885252089750919566836183252857475484338913841291095222387779067564971983760619814471104385614285949705697261702933899278537712383849527252611987939947273446907728942539157463443880598175266703887,
            89537174583470428126368559122733093792771267470145172261204043737374783295746735770977275377863486022234354929860172558745137290320682223277990399066906105916137221611218740752167456538787695936927885201842306174187254104613077236292789788064415254034851612157179926431228950237250716554645306298514263908811,
            106012262050781200106909327696665817682864459575156325008493049499578896429709338134583432679663875229243561266610327817994340312544432988100581205278527652776797129380732775139010348828146830433114148695545628251479471386655045041620711043660854155633665634387716779804052874716264079804365681200926368878541,
            98047438997515280074792701497622826536971900999197902469801657195397532486098993597664864573258672004307512856021908739030566926963054863998516343042890871462635847748128662678669505745602483507470396856696130729682439145004123654578085621747843892166517045343501758093052905936670793527374604000360320123643,
            48107859163997579694864893504886560528514286462252528518753580114887818750322128218646068205130016527298578884960923054955072510745551784643455001265439464144751949280776912819502350769576504234639747590328838926697492194274517633949025303073843002256820311079628923909309353364288514091223779706534988233353,
            95193465162148191217844814565725476305218769551232988131351154011966624770961320486395571928859840281251870272532908194236488486001519948267693888769624645565515338392649711205572847326959985300653388437498035890136677149175252923464027081780534454300684502200232492689914254307896522690747556123142494605401,
            168489441676498254188251084620317730514271361861339944910962927459542807975808481932360687459768443345754506784027235857753721317508760585508375364503886428020727192193297507131796130690248490645731180656182669717283026722056291513041731668953221561576833358510127447655469989100576330621949276177058083620677,
            127791896675045040395064468573109425010219774613093240038326469106056928318395608480165676859635771156871330139281596703754063207095456065784747740162970184880536590144647003492364759169502217854388165521994268206346785403332622195574508223431200064645819724980706217912475871209058082764033948277691466089251
        ]

        for idx, mod in enumerate(fake_mods):
            r1 = fprinter_moduli.process_mod_line_num(mod, str(idx), 0, num_type='dec')
            r2 = fprinter_dlog.process_mod_line_num(mod, str(idx), 0, num_type='dec')
            self.assertTrue(r1.marked, 'Moduli detector should have detect %d mod' % idx)
            self.assertFalse(r2.marked, 'Dlog detector should have detect %d mod' % idx)


if __name__ == "__main__":
    unittest.main()  # pragma: no cover


