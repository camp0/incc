__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import random
import ctypes
import sys
sys.path.append("../src/core/")
import incc_test as p
import unittest
import testrunner

class Test_01(unittest.TestCase):

    	def setUp(self):
		self.pool = p.FLPO_Init()
		
	def tearDown(self):
		p.FLPO_Destroy(self.pool)

	def test_01_1(self):
		"Test the flowpool I"
		value = p.FLPO_GetNumberFlows(self.pool)
		temp = list()
		p.FLPO_DecrementFlowPool(self.pool,100)
		for i in xrange(0,100):
			h = p.FLPO_GetFlow(self.pool)
			temp.append(h)

		self.assertEqual(value-200,p.FLPO_GetNumberFlows(self.pool))
		for h in temp:
			p.FLPO_AddFlow(self.pool,h)

		self.assertEqual(value-100,p.FLPO_GetNumberFlows(self.pool))

        def test_01_8(self):
                "Test the flowpool II"
                value = p.FLPO_GetNumberFlows(self.pool)
                temp = list()
                for i in xrange(0,value):
                        h = p.FLPO_GetFlow(self.pool)
                        temp.append(h)

		for i in xrange(0,5):
			h = p.FLPO_GetFlow(self.pool)
			self.assertEqual(None,h)

		self.assertEqual(5,self.pool.total_errors)
                for h in temp:
                        p.FLPO_AddFlow(self.pool,h)

		p.FLPO_AddFlow(self.pool,None)
                self.assertEqual(value,p.FLPO_GetNumberFlows(self.pool))

        def test_01_9(self):
                "Test the flowpool III"
		pool = p.FLPO_Init()
                value = p.FLPO_GetNumberFlows(pool)
                temp = list()
                for i in xrange(0,value):
                        h = p.FLPO_GetFlow(pool)
                        temp.append(h)

                for i in xrange(0,5):
                        h = p.FLPO_GetFlow(pool)
                        self.assertEqual(None,h)

                self.assertEqual(5,pool.total_errors)
                for h in temp:
                        p.FLPO_AddFlow(pool,h)
		
                p.FLPO_AddFlow(pool,None)
                self.assertEqual(value,p.FLPO_GetNumberFlows(pool))
                h = p.FLPO_GetFlow(pool)
                h = p.FLPO_GetFlow(pool)
                h = p.FLPO_GetFlow(pool)
                self.assertEqual(value-3,p.FLPO_GetNumberFlows(pool))
		p.FLPO_Destroy(pool)

        def test_01_10(self):
                "Test the flowpool IV"
                pool = p.FLPO_Init()
                value = p.FLPO_GetNumberFlows(pool)
                temp = list()
                for i in xrange(0,value):
                        h = p.FLPO_GetFlow(pool)
                        temp.append(h)

                self.assertEqual(0,pool.total_errors)
                for h in temp:
			p.GEFW_Destroy(h)

                self.assertEqual(0,p.FLPO_GetNumberFlows(pool))
                h = p.FLPO_GetFlow(pool)
                h = p.FLPO_GetFlow(pool)
                h = p.FLPO_GetFlow(pool)
                self.assertEqual(0,p.FLPO_GetNumberFlows(pool))
                p.FLPO_Destroy(pool)

class Test_02(unittest.TestCase):

        def setUp(self):
        	pass 

        def tearDown(self):
		pass
        
	def test_02_1(self):
                "Test the payloads I"
		cadena = "buffer to encrypt"
		key = "theKey"
		head = "pepe"
		tail = None
		payload = p.PYLD_GeneratePayload(key,head,tail,cadena,len(cadena))

		self.assertEqual(payload.len,len(cadena)+len(head)+4)
		newpayload = p.PYLD_RecoverPayload(key,payload,head,tail)
		self.assertEqual(len(cadena),newpayload.len)
		self.assertEqual(cadena,newpayload.payload[:newpayload.len])
		p.PYLD_Destroy(payload)
		p.PYLD_Destroy(newpayload)

        def test_02_2(self):
                "Test the payloads II"
		key = "theKey"
                cadena = "buffer to encrypt"
                head = "pepe"
                tail = "algo mas"
                payload = p.PYLD_GeneratePayload(key,head,tail,cadena,len(cadena))

                self.assertEqual(payload.len,len(cadena)+len(head)+len(tail)+4)
                newpayload = p.PYLD_RecoverPayload(key,payload,head,tail)
                self.assertEqual(len(cadena),newpayload.len)
                self.assertEqual(cadena,newpayload.payload[:newpayload.len])
		p.PYLD_Destroy(payload)
		p.PYLD_Destroy(newpayload)

        def test_02_3(self):
                "Test the payloads III"
                cadena = "buffer to encrypt"
		key = "theKey"
                head = "pepe"
                tail = "algo mas"
                payload = p.PYLD_GeneratePayload(key,head,tail,cadena,len(cadena))

		p_tmp = payload.payload
		p_len = payload.len
		payload.payload = "nothing to recoverRRR"
		payload.len = len(payload.payload)

                newpayload = p.PYLD_RecoverPayload(key,payload,head,tail)
                self.assertEqual(newpayload,None)
		payload.payload = p_tmp
		payload.len = p_len
                newpayload = p.PYLD_RecoverPayload(key,payload,head,tail)
                self.assertNotEqual(newpayload,None)

		# the payload is recovered

                self.assertEqual(len(cadena),newpayload.len)
                self.assertEqual(cadena,newpayload.payload[:newpayload.len])

		p.PYLD_Destroy(payload)
		p.PYLD_Destroy(newpayload)

        def test_02_4(self):
                "Test the payloads IV"
		key = "theKey"
                cadena = "buffer to encrypt"
                head = "pepe"
                tail = "algo mas"
                payload = p.PYLD_GeneratePayload(key,head,tail,cadena,len(cadena))

                p_tmp = payload.payload
                p_len = payload.len
                payload.payload = "nothing"
                payload.len = len(payload.payload)

                newpayload = p.PYLD_RecoverPayload(key,payload,head,tail)
                self.assertEqual(newpayload,None)
                payload.payload = p_tmp
                payload.len = p_len
                newpayload = p.PYLD_RecoverPayload(key,payload,head,tail)
                self.assertNotEqual(newpayload,None)

                self.assertEqual(len(cadena),newpayload.len)
                self.assertEqual(cadena,newpayload.payload[:newpayload.len])

                p.PYLD_Destroy(payload)
                p.PYLD_Destroy(newpayload)
		
        def test_02_5(self):
                "Test the payloads V (tail)"
		key = "theKey"
                cadena = "buffer to encrypt"
                head = None 
                tail = "AAAA"
                payload = p.PYLD_GeneratePayload(key,head,tail,cadena,len(cadena))

		cad = payload.payload[len(cadena)+4:][:4]
		self.assertEqual(payload.len,len(cadena)+len(tail)+4)
		self.assertEqual(cad,tail)

                p.PYLD_Destroy(payload)

        def test_02_6(self):
                "Test the payloads VI (short)"
		key = "theKey"
                cadena = "cool"
                head = "SOME" 
                tail = "AAAA"
                payload = p.PYLD_GeneratePayload(key,head,tail,cadena,len(cadena))

                self.assertEqual(payload.len,len(cadena)+len(tail)+4+len(head))
		newpayload = p.PYLD_RecoverPayload(key,payload,head,tail)
               
		self.assertEqual(newpayload.payload[:newpayload.len],cadena)
		p.PYLD_Destroy(newpayload) 
		p.PYLD_Destroy(payload)


if __name__ == '__main__':
	print "Testing incop modules"
	suite=unittest.TestSuite()
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_01))
    	suite.addTest(unittest.TestLoader().loadTestsFromTestCase(Test_02))
	result=testrunner.BasicTestRunner().run(suite)
	
