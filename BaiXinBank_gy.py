# -*- coding: utf-8 -*-
"""
# @time         : 2023/11/13 09:29
# @author       : ZhangWei
# @fileName     :
# @description  : 百信银行
# @details_url :
    精选理财 https://wmt.aibank.com/finances/app/#/financesubsx/1/0/0/0
    钱包plus https://wmt.aibank.com/qbplus/app/#/acctplus/home
    产品详情页：https://wmt.aibank.com/finances/app/#/financesub/openType/detail/PP03312096
"""
import sys
from time import strptime
from jsonpath import jsonpath

from utils import AppSpider
from utils.config import *
from utils.etl_data.etl_func import *
from utils.spider_middle.down_middle import *
from utils.request_lib.request_package import send_request
from base64 import b64decode, b64encode
from Crypto.Cipher import DES3
from Crypto.Hash import MD5
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA


class TripleDESEncryptor:
    def __init__(self, base64_key):
        self.key = b64decode(base64_key)
        self.cipher = DES3.new(self.key, DES3.MODE_ECB)

    def encrypt(self, plain_text):
        plain_text = self.pkcs5_pad(plain_text.encode())  # 使用PKCS5Padding填充明文
        encrypted_bytes = self.cipher.encrypt(plain_text)  # 加密
        return b64encode(b64encode(encrypted_bytes)).decode()  # 返回经过base64编码的密文

    def decrypt(self, cipher_text):
        decrypted_bytes = self.cipher.decrypt(b64decode(b64decode(cipher_text)))  # 解密
        plain_text = self.pkcs5_unpad(decrypted_bytes).decode('utf-8')  # 去除填充
        return plain_text

    def pkcs5_pad(self, text, block_size=8):
        padding_size = block_size - len(text) % block_size
        padding = bytes([padding_size] * padding_size)
        return text + padding

    def pkcs5_unpad(self, text):
        padding_size = text[-1]
        if padding_size < 1 or padding_size > 8:
            return text
        return text[:-padding_size]


class BaiXinBank_(AppSpider):
    def __init__(self, spider_key='中信百信银行', log_id=-1, task_id=-1, task_touch_off_time='', debugger=True):
        super().__init__(spider_key, log_id, task_id, task_touch_off_time, debugger)
        self.version = 'Android 5.6.0'
        self.proxy = True
        self.init()
        self.sp_chan_name = '百信银行'  # 应用名
        # spider_key 机构名
        self.headers = {
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'zh-CN,zh;q=0.9',
            'Content-Type': 'application/json',
            'Origin': 'https://wmt.aibank.com',
            'Referer': 'https://wmt.aibank.com/finances/app/',
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 Edg/119.0.0.0',
        }
        self.des = TripleDESEncryptor('8l44a7xd7M5545de93x8ddb3eob0be98')
        self.spider_table = 'all'    # 表示抓所有表
        self.spider_ann_num = 'all'  # 表示抓取每个产品的所有公告文件
        self.spider_net_num = 'all'  # 表示抓取每个产品的所有净值数据

    def init(self):
        self.mp_mongo_name = {
            'base': MONGO_COL_BASE_INFO,
            'cycle': MONGO_COL_CYCLE_INFO,
            'market': MONGO_COL_MARKET_INFO,
            'anno': MONGO_COL_ANNOUNCEMENT_INFO,
            'tag': MONGO_COL_TAG_INFO,
            'rate': MONGO_COL_FEE_INFO,
            'comb': MONGO_COL_COMB_SALE_INFO,
        }
        mp_key = {'base': 'basic', 'anno': 'announcement', 'tag': 'tags',
                  'rate': 'fee', 'cycle': 'cycle', 'market': 'market', 'comb': 'comb'}

        self.parse_fun = {}
        self.format_dict_key = {}
        self.format_base_dict = {}
        self.format_fun = {}
        self.log_tags = {}  # = {
        #     'base': '[基础信息]',
        #     'cycle': '[期间状态]',
        #     'market': '[净值信息]',
        #     'tag': '[标签信息]',
        #     'anno': '[公告信息]',
        #     'rate': '[费率信息]',
        # }

        for key, value in self.mp_mongo_name.items():
            self.parse_fun[key] = getattr(self, 'parse_' + key)  # 根据key获取对应的方法
            self.format_dict_key[key] = mp_key[key] + '_info'
            self.format_base_dict[key] = getattr(self, mp_key[key] + '_info')  # 根据key获取对应的字典
            self.format_fun[key] = globals()['format_' + mp_key[key] + '_info']  # 根据key获取对应的方法
            self.log_tags[key] = '[' + self.format_dict_key[key].capitalize() + ']'

    def wrap_request_post(self, url: str, data: dict) -> str:
        """ 包装请求做请求前的加解密 """
        ret = ''

        data_json = json.dumps(data, ensure_ascii=False, separators=(',', ":")).encode('utf-8')
        encoded_data = b64encode(data_json).decode('utf-8')
        json_data = {'data': encoded_data}

        response = send_request.post(url, headers=self.headers, json=json_data)
        try:
            ret = b64decode(response.json()['data']).decode('utf-8')
        except Exception as e:
            ...

        return ret

    def wrap_request_post_plus(self, url: str, p_data: dict, url2: str) -> str:
        """ 包装请求做请求前的加解密 """
        ret = ''
        tx_cd = url[url.rfind('/') + 1:]
        to_sys_tem_id = url[:url.rfind('/')][url[:url.rfind('/')].rfind('/') + 1:]
        ret_data = {
            "head": {"App_Id": "APP_AIBANK_DES", "Charset": "UTF-8", "Sign_Type": "3DES", "Sign": "", "msg_type": "01", "Tx_CD": tx_cd, "TxnSrlNo": "*", "To_SysTem_ID": to_sys_tem_id},
            "body": {"msg_content": ""}
        }
        des_en_plaintext = {'clientHeader': {'uuid': '', 'accessToken': None, 'timestamp': ''}, 'jsonParams': '', 'url': url2}
        try:
            # jsonParams base64
            json_params_str = json.dumps(p_data, separators=(',', ":")).encode()
            des_en_plaintext['jsonParams'] = b64encode(json_params_str).decode()

            # msg_content 3des
            msg_content_str = json.dumps(des_en_plaintext, separators=(',', ":"))
            ret_data['body']['msg_content'] = self.des.encrypt(msg_content_str)
            ret_data['head']['Sign'] = self.rsa_signature(msg_content_str)  # sign

            r = send_request.post(url, headers=self.headers, json=ret_data)

            r_msg_content = r.json()['body']['msg_content']
            r_msg_content_de = json.loads(self.des.decrypt(r_msg_content))['data']
            ret = json.loads(b64decode(r_msg_content_de))
        except Exception as e:
            self.logger.exception(e)

        return ret

    def get_prd_list(self) -> list:
        ret_prd_list = []
        # saleStatus(1) 售罄
        url = 'https://wmt.aibank.com/app/api/wsp/access/getSceneTagBsfPrdList'
        data = {"category_code": "CA003", "version_no": "1", "transaction_code": "100428", "pageScene": "FINANCE001", "tagType": 1,
                "tagName": "全部", "orderName": "收益率", "orderSort": "22", "startPosition": 0, "queryNumber": 9999, "saleStatus": 1,
                "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}

        for sale_status in [3, 2, 1]:
            data['sale_status'] = sale_status
            rsp = self.wrap_request_post(url, data)

            try:
                ret_prd_list.extend(eval(rsp)['tag_prd_info_list'])
            except Exception as e:
                ...
        return ret_prd_list

    def get_wallet_plus_list(self) -> []:
        ret = []
        url = 'https://wmt.aibank.com/app/api/wsp/access/queryProductList'
        data = {"version_no": "1", "transaction_code": 100439, "prddaily_desc_or_asc": "",
                "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}
        try:
            r = self.wrap_request_post(url, data)
            ret = eval(r)['products']
        finally:
            return ret

    def request_detail(self, prd_code: str = "PP03212042") -> dict:
        ret = {}
        url = "https://wmt.aibank.com/app/api/wsp/access/getBankFinanceInfo"
        data = {"product_no": prd_code, "product_id": "140001", "taCode": "", "version_no": "1", "transaction_code": "100003",
                "time_axis_type": "1", "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}
        try:
            ret = eval(self.wrap_request_post(url, data))
        except Exception as e:
            ...

        return ret

    @staticmethod
    def rsa_signature(data: str):
        data = MD5.new(data.encode()).hexdigest().upper()

        private_key_str = """-----BEGIN PRIVATE KEY-----
        MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBALxjAKCKrPkKoDfoQpt5Wx/Uhu+hv9PxNLe6Ua93jNXGeb6iQThUg0dRjTbKqMtn7dJdBdd4Nso0jrp399ZSbs1RMLVIPlsssc4IklOpnVIwwyGOPSJ9j7b/6jmCqnzWLwuU/aQ7Wswu+KHlfUxUzKpdfkh6D/KVkOklWhpVa8ZNAgMBAAECgYEAqYBOtSRxZBbKd+Mz4x36/pXD32Li7bjOnS04iC+B+Wr+aacmFZ/9CrN24sDPxUy6sBdgxTF14tQNQ/vjc+RxqiG9BKwjugfMlb95p1ta5LL7bV65+hNGllWLFXXgQ6q9WN8vHUEeQRi8hl4YAb8jZtWtLow66sQ7MQ3gpj/DjqUCQQDhSM7NWXAScAffM7tFyHuNxld7nRbHYFugoVXxLX85nVhEvFjnyaTW2Sqgi6r9iXWDoD6g5bl7meLuOLY5Z7B7AkEA1hJXFSJXBOLF3ta5DOS/3Lbzrh/U6uiW2nLhCZX9kXNi1IHtYbIzF5XLgeMQxFOqNBGa0teBk4iHn7QLGrf91wJADjiTXWEc8v0BcjSIyNHsAroXgaUb8AAEKLKmgy/1DQUCsmwVTKRs9GcHCtVmONT5hxKRgYSe3c+MBK+tyRfjiwJAZdcvyoQdtdtUmyC3xGSGyi/XWb0XA/JG4gHJAVBz42BrYgG1tsaZ+9xthotJjLzougCuESQpJtDLBLUYm0tw3QJAIok/5IU7S95NPfZfwiePRtV06dj5JSRjMzUzVqyBnZSC26V054J5v5dgi0OO/Awzd6cXZ8YQf0GbO7vL5BzX4g==
        -----END PRIVATE KEY-----"""

        # 创建RSA密钥对象
        private_key = RSA.importKey(private_key_str)

        # 使用PKCS1_v1_5进行签名
        h = MD5.new(data.encode('utf-8'))
        signer = PKCS1_v1_5.new(private_key)
        signature = signer.sign(h)

        # 返回签名结果
        return b64encode(signature).decode()

    def request_plus_detail(self, prd_code: str = "A21005") -> dict:
        ret = {}
        url = "https://open-customer.aibank.com/APP_AIBANK_DES/AI_WSP_001/AIWSP00010"
        data = {
            "head": {"App_Id": "APP_AIBANK_DES", "Charset": "UTF-8", "Sign_Type": "3DES", "Sign": "",
                     "msg_type": "01", "Tx_CD": "AIWSP00010", "TxnSrlNo": "fb414909-7905-458e-986e-53a4b4f29a46",
                     "To_SysTem_ID": "AI_WSP_001"},
            "body": {"msg_content": ""}
        }
        try:
            jsonParams = {"version_no": "1", "transaction_code": "100438", "prdCode": prd_code, "invest_source": "1",
                          "invest_channel": "1", "req_channel": "1", "req_source": "1"}
            msg_content_dict = {'clientHeader': {'uuid': '19324ec25324438681a0588370200241', 'accessToken': None, 'timestamp': 1700027671148},
                                'jsonParams': '', 'url': 'queryProduct'}
            json_params_str = json.dumps(jsonParams, separators=(',', ":")).encode()
            msg_content_dict['jsonParams'] = b64encode(json_params_str).decode()

            msg_content_str = json.dumps(msg_content_dict, separators=(',', ":"))

            data['body']['msg_content'] = self.des.encrypt(msg_content_str)
            data['head']['Sign'] = self.rsa_signature(msg_content_str)  # sign
            response = send_request.post(url, headers=self.headers, json=data)

            # 响应解解密
            msg = response.json()['body']['msg_content']
            p = json.loads(self.des.decrypt(msg))['data']
            ret = eval(b64decode(p).decode())['product_detail']
        finally:
            return ret

    def req_net_value_list(self, prd_code: str = 'PP03312019') -> list:
        ret = []
        url = 'https://wmt.aibank.com/app/api/wsp/access/getBankFinanceYieldAndIncomeUnit'
        data = {"product_no": prd_code, "product_id": "140001", "taCode": "", "version_no": "1", "transaction_code": "100028",
                "startPosition": 0, "queryNumber": "9999", "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}
        post = self.wrap_request_post(url, data)
        try:
            # current_time = strftime('%Y%m%d')[:-2] + '01'  # 202312 + 01
            nav_common_list = eval(post)['nav_common_list']
            # ret = [i for i in nav_common_list if i['issue_date'] >= int(current_time)]  # 只取当前月
            ret = nav_common_list
        except Exception as e:
            ...
        return ret

    def req_plus_ann_yield_list(self, prd_code: str = '9TTL005J') -> list:
        """plus 七日年化与万份收益"""
        ret = []
        # days(7/30/182/365)
        url = "https://open-customer.aibank.com/APP_AIBANK_DES/AI_MPB_001/AIMPB00017"
        data = {"url": "queryPrddailyList", "prdCode": prd_code, "days": 365, "channel_type": "", "investChannel": "1", "investSource": "1", "req_channel": "1", "req_source": "1"}
        post = self.wrap_request_post_plus(url, data, 'execIfmCommonTrans')
        try:
            prddaily_detail_list = jsonpath(post, '$..prddaily_detail_list')
            if prddaily_detail_list:
                current_time = strftime('%Y%m%d')[:-2] + '01'  # 202312 + 0
                ret = [i for i in prddaily_detail_list[0] if i['iss_date'] >= int(current_time)]  # 只取当前月
                ret = [{'ann_yield_7d': f"{round(i['seven_rate'] * 100, 6)}",
                        'issue_date': i['iss_date'], 'ten_ths_earn': i['tenth_income']} for i in ret]
                # [{...},{...},{...}]
                # tenth_income(万份收益) seven_rate(七日年化)
                # {'seven_rate': 0.04665, 'tot_nav': 1.0, 'nav': 1.0, 'prd_code': '9TTL005J', 'tenth_income': 1.1051, 'iss_date': 20231228, 'cfm_date': 20231229, 'ta_code': 'Y05'}
        except Exception as e:
            self.logger.exception(e)
        return ret

    def req_chg_and_anny(self, prd_code: str = 'PP03312019') -> dict:
        """涨跌幅/历史年化"""
        ret = {}
        url = 'https://wmt.aibank.com/app/api/wsp/access/queryFinanceChgAndReturnRate'
        data = {"version_no": "1", "transaction_code": "100455", "product_no": prd_code,
                "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}
        post = self.wrap_request_post(url, data)
        try:
            iss_date = eval(post)['iss_date']
            ret = {'his_net_value_date': iss_date}
            detail_list = eval(post)['detail_list']
            for detail in detail_list:
                caliber_code = detail['caliber_code']
                if caliber_code == '3':
                    ret['chg_ratio_1m'] = detail['chg_show'].replace('%', '')  # 涨跌幅
                    ret['ann_yield_1m'] = detail['yield_show'].replace('%', '')  # 年化收益率
                elif caliber_code == '4':
                    ret['chg_ratio_3m'] = detail['chg_show'].replace('%', '')
                    ret['ann_yield_3m'] = detail['yield_show'].replace('%', '')
                elif caliber_code == '5':
                    ret['chg_ratio_6m'] = detail['chg_show'].replace('%', '')
                    ret['ann_yield_6m'] = detail['yield_show'].replace('%', '')
                elif caliber_code == '6':
                    ret['chg_ratio_1y'] = detail['chg_show'].replace('%', '')
                    ret['ann_yield_1y'] = detail['yield_show'].replace('%', '')
                elif caliber_code == '10':
                    ret['chg_ratio_esta_to_day'] = detail['chg_show'].replace('%', '')
                    ret['ann_yield_esta_to_day'] = detail['yield_show'].replace('%', '')
        except Exception as e:
            self.logger.error(e)
        return ret

    def req_plus_anno_list(self, prd_code: str = "JQB2332C") -> list:
        ret = []
        url = 'https://open-customer.aibank.com/APP_AIBANK_DES/AI_WSP_001/AIWSP00010'
        data = {"version_no": "1", "transaction_code": "100051", "paramKey": f"acctplus_product_:{prd_code}",
                "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}
        post_plus = self.wrap_request_post_plus(url, data, 'getPageParam')
        try:
            ret = eval(post_plus['param_value'])['announcementList']
            # [{'title': '关于杭银理财幸福99金钱包32号理财（JQB2332）调整部分产品要素的公告-1225', 'uri': 'https://mres.aibank.com:60088/app/resource/ifm/ifm0000047/关于杭银理财幸福99金钱包32号理财（JQB2332）调整部分产品要素的公告-1225.html'}]
        except Exception as e:
            ...
        return ret

    def req_anno_list(self, prd_code: str = "PP03212061") -> list:
        ret = []
        url = 'https://wmt.aibank.com/app/api/wsp/access/getProductDocList'
        data = {"version_no": "1", "transaction_code": "100027", "product_no": prd_code, "doc_type": "3",
                "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}
        post = self.wrap_request_post(url, data)
        try:
            doc_list = jsonpath(eval(post), '$..doc_list')
            if doc_list:
                ret = [{'title': i['doc_name'],
                        'uri': i['doc_url'],
                        'date': i['publish_date']} for i in doc_list[0]]
        except Exception as e:
            self.logger.info(e)
        return ret

    def net_value_parse(self, type_, value, net_value_data):
        """
        将每一个产品的每一条净值数据解析并存储oss,mongo
        """
        net_value_md5_value = create_md5(str(value))
        data_status = mongo_duplication_data_compare(self.mp_mongo_name[type_], net_value_md5_value,
                                                     key_field='oss_md5')
        if not data_status:
            net_value_oss_path, net_value_cdn_url = data_insert_oss(self.path, value, self.target_bank_name,
                                                                    net_value_md5_value + '.txt')
            net_value_data['oss_path'] = net_value_oss_path
            net_value_data['cdn_url'] = net_value_cdn_url
            net_value_data['oss_md5'] = net_value_md5_value
            date_str = net_value_data['his_yield_list'][0].get('his_net_value_date', '') if net_value_data[
                'his_yield_list'] else strftime('%Y-%m-%d')
            if date_str:
                date_str = date_str.replace('.', '').replace('-', '').replace('/', '')
                date_str = datetime.strptime(date_str, '%Y%m%d').strftime('%Y-%m-%d')
            net_value_data = self.format_fun[type_](**net_value_data)
            net_value_data['net_value_date'] = date_str
            if net_value_data is not True:
                self.dbs(col_name=self.mp_mongo_name[type_], **net_value_data)
        return

    @AppSpider.catch_the_error
    def base(self, type_: str, data: list):
        """
        type_: 产品类型: base/cycle/market/anno/tag/rate
        product_name: 产品名称
        all_data: 产品所有请求的原始数据
        mongo_name: mongo表名
        """
        index = data[0] + 1
        total = data[2]
        dicts: dict = data[1]
        prd_code = dicts.get('product_common', {}).get('product_no', '') or dicts.get('prd_code', '')
        prd_name = dicts.get('product_common', {}).get('product_name', '') or dicts.get('prd_name', '')
        self.logger.info(f'({index}/{total}) {self.log_tags[type_]} {prd_code} {prd_name}')
        all_data = [dicts]

        parse_fun = self.parse_fun[type_]

        # 钱包plus
        if 'product_common' in dicts:
            if type_ == 'base':
                all_data.extend([self.request_detail(prd_code)])
            elif type_ == 'cycle':
                all_data.extend([self.request_detail(prd_code)])
            elif type_ == 'market':
                all_data.extend([self.req_net_value_list(prd_code)])
                all_data.extend([self.req_chg_and_anny(prd_code)])
            elif 'anno' in type_:
                all_data.extend([self.req_anno_list(prd_code)])
            elif 'tag' in type_:
                all_data.extend([self.request_detail(prd_code)])
        else:
            if 'base' in type_:
                parse_fun = self.parse_base1
                all_data.extend([self.request_plus_detail(prd_code)])
            elif 'cycle' in type_:
                parse_fun = self.parse_cycle1
            elif 'market' in type_:
                all_data.extend([self.req_plus_ann_yield_list(prd_code)])
            elif 'anno' in type_:
                all_data.extend([self.req_plus_anno_list(prd_code)])
            elif 'tag' in type_:
                return

        md5_value = create_md5(str(all_data) + prd_name)
        # 2.判断重复（如果重复则更新mongo中该条数据的update以及mongo中元数据表的中该条数据的update,并结束程序，否则走以下解析流程）
        data_status = mongo_duplication_data_compare(self.mp_mongo_name[type_], md5_value, key_field='oss_md5')
        if not data_status:
            # 3.原始数据入oss（数据需要存成txt文件后）
            oss_path, cdn_url = data_insert_oss(self.path, all_data, self.target_bank_name, md5_value + '.txt')

            # 4.解析详情页信息
            basic_info: dict = parse_fun(prd_name, prd_code, md5_value, oss_path, cdn_url, all_data)

            if basic_info is True:  # True表示结果数据有重复，不再入库
                return
            else:  # 5.数据存储入mongo
                self.dbs(col_name=self.mp_mongo_name[type_], **basic_info)
        return

    def format_info(self, type_, md5_value, oss_path, cdn_url, prd_name, prd_code, t_data: dict):
        data = {
            'oss_path': oss_path, 'cdn_url': cdn_url, 'oss_md5': md5_value, 'sp_chan_ver': self.version,
            'sp_chan_name': self.sp_chan_name, 'sp_ins_name': self.target_bank_name, 'sp_obj_id': prd_code,
            'prod_name': prd_name, 'bank_prod_code': prd_code,
            f'{self.format_dict_key[type_]}': self.format_base_dict[type_]
        }
        if type_ == 'comb':
            del data['prod_name']
            del data['bank_prod_code']

        data.update(t_data)

        # # 2024.05.20根据口述需求将净值的数据解析和存储从最小颗粒度为产品，修改成最小颗粒度为每个产品的每条净值数据
        # if type_ == 'market':
        #     his_yield_list = data['his_yield_list']
        #     for i in his_yield_list:
        #         data['his_yield_list'] = [i]
        #         self.net_value_parse(type_, i, data)
        #     return True

        return self.format_fun[type_](**data)

    def req_qa(self, prd_code: str = 'PP03212042') -> str:
        ret = ''
        url = 'https://wmt.aibank.com/app/api/wsp/access/getPageParam'
        data = {"invest_channel": "1", "invest_source": "1", "paramKey": f"financesub_common_faq_:{prd_code}",
                "req_channel": "1", "req_source": "1", "transaction_code": "100051", "version_no": "1"}

        try:
            param_value = eval(self.wrap_request_post(url, data))['param_value']
            param_list = eval(param_value)['list']
            parse_list = [f"{i['q']}:{''.join(i['a'])}" for i in param_list if '常见问题内容仅供参考' not in i['q']]
            ret = '\n'.join(parse_list)
        except:
            pass

        return ret

    def req_get_rule(self, prd_code: str = 'PP03212042') -> str:
        """ 购买,确认,赎回规则 """
        ret = ''
        url = 'https://wmt.aibank.com/app/api/wsp/access/getPageParam'
        data = {"invest_channel": "1", "invest_source": "1", "paramKey": f"financesub_common_tradeRule_:{prd_code}",
                "req_channel": "1", "req_source": "1", "transaction_code": "100051", "version_no": "1"}

        try:
            param_value = eval(self.wrap_request_post(url, data))['param_value']
            ret = eval(param_value)['rules']
        except Exception as e:
            self.logger.info(f'购买,确认,赎回规则 {e}')

        return ret

    def req_get_doc(self, prd_code: str = 'PP03212042') -> str:
        """ 获取文档 """
        ret = ''
        url = 'https://wmt.aibank.com/app/api/wsp/access/getProductDocList'
        data = {"doc_type": "1", "invest_channel": "1", "invest_source": "1", "product_no": prd_code,
                "req_channel": "1", "req_source": "1", "transaction_code": "100027", "version_no": "1"}

        try:
            doc_list = eval(self.wrap_request_post(url, data))['doc_list']
            ret = doc_list[0]['doc_url'] if doc_list[0]['doc_name'] == "产品说明书" else ''
        except:
            pass

        return ret

    def parse_base(self, prd_name, prd_code, md5_value, oss_path, cdn_url, data: list):
        prd_list = data[0]
        detail = data[1] if len(data) > 1 else {}

        inv_cycle = detail.get('product_desc', '')  # 投资周期
        issue_ins = detail.get('ta_name', '')  # 发行机构
        prod_feat = '\n'.join([f'{i["feature_name"]}：{i["feature_desc"]}' for i in detail.get('product_feature_list', [])])  # 产品特色
        issue_ins_risk_rank = detail.get('risk_level_name', '')  # 发行机构风险等级
        benchmark = detail.get('prd_benchmark', '')  # 业绩比较基准
        if benchmark == '首发热销':
            benchmark = re.findall('业绩比较基准[ ]*(.*?)%', detail.get('prd_benchmark_more_desc', ''))
            benchmark = benchmark[0] if benchmark else ''
        benchmark_calc = detail.get('prd_benchmark_more_desc', '')  # 业绩比较基准测算依据
        prod_esta_date = detail.get('product_estab_date', '')  # 产品成立日
        prod_intr_path = detail.get('bx_specail_picture_url', '')  # 产品介绍
        qa = self.req_qa(prd_code)  # 常见问题
        if '【{{$cache.prd_benchmark}}】' in qa:
            qa = qa.replace('【{{$cache.prd_benchmark}}】', benchmark)

        prod_spec_path = self.req_get_doc(prd_code)  # 产品说明书
        min_pur_amt = f"{detail['min_buy_amount']}元" if detail.get('min_buy_amount') else ''  # 起购金额
        incr_amt = f"{detail['min_buy_unit']}元" if detail.get('min_buy_unit') else ''  # 递增金额
        pur_rule = ''  # 购买规则
        pur_conf_rule = ''  # 购买确认规则
        rede_rule = ''  # 赎回规则
        rede_conf_rule = ''  # 赎回确认规则
        rules = self.req_get_rule(prd_code)
        for rule in rules:
            title = rule['title']
            detail_ = '\n'.join(rule['detail'])
            if title == '申请购买规则':
                # '{{$cache.min_buy_amount | handleAmount}}元起购，{{$cache.min_buy_unit | handleAmount}}元整数倍递增
                # 投资者可在每个工作日的交易时间内进行申购
                # 申购无手续费'
                detail_ = detail_.replace('{{$cache.min_buy_amount | handleAmount}}', str(detail.get('min_buy_amount', '')))
                detail_ = detail_.replace('{{$cache.min_buy_unit | handleAmount}}', str(detail.get('min_buy_unit', '')))
                pur_rule = detail_
            elif title == '申购确认规则':
                pur_conf_rule = detail_
            elif title == '申请赎回规则':
                rede_rule = detail_
            elif title == '赎回确认规则':
                rede_conf_rule = detail_

        # 图片下载保存
        if prod_intr_path:
            file_name = f'产品介绍_{md5_value}.jpg'
            r = send_request.get(prod_intr_path)
            result = data_insert_oss(self.path, r, self.target_bank_name, file_name)
            if result:
                prod_intr_path, prod_spec_cdn_url = result
            else:
                prod_intr_path = ''

        # 产品说明书保存
        if prod_spec_path:
            prod_spec_path = ''
            r = send_request.get(prod_spec_path)
            if r:
                re_ret = re.findall(r"atob\(`(.*?)`", r.text)
                if re_ret:
                    prd_bytes = b64decode(re_ret[0])
                    prod_spec_path, _ = data_insert_oss(self.path, prd_bytes, self.target_bank_name, f'产品说明书_{md5_value}.pdf')

        data = {
            'inv_cycle': inv_cycle,  # 投资周期
            'issue_ins': issue_ins,  # 发行机构
            'prod_feat': prod_feat,  # 产品特色
            'issue_ins_risk_rank': issue_ins_risk_rank,  # 发行机构风险等级
            'benchmark': benchmark,  # 业绩比较基准
            'benchmark_calc': benchmark_calc,  # 业绩比较基准测算依据
            'prod_esta_date': prod_esta_date,  # 产品成立日
            'prod_intr_path': prod_intr_path,  # 产品介绍
            'qa': qa,  # 常见问题
            'prod_spec_path': prod_spec_path,  # 产品说明书
            'min_pur_amt': min_pur_amt,  # 起购金额
            'incr_amt': incr_amt,  # 递增金额
            'pur_rule': pur_rule,  # 购买规则
            'pur_conf_rule': pur_conf_rule,  # 购买确认规则
            'rede_rule': rede_rule,  # 赎回规则
            'rede_conf_rule': rede_conf_rule  # 赎回确认规则
        }

        return self.format_info('base', md5_value, oss_path, cdn_url, prd_name, prd_code, data)

    def req_get_plus_rule_anno(self, prd_code) -> dict:
        """ 钱包Plus 规则与公告 """
        ret = {}
        url = 'https://wmt.aibank.com/app/api/wsp/access/getPageParam'
        data = {"version_no": "1", "transaction_code": "100051", "paramKey": f"acctplus_product_:{prd_code}",
                "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}
        try:
            r = self.wrap_request_post(url, data)
            param_value = eval(r)['param_value']
            ret = eval(param_value)
        finally:
            return ret

    def parse_base1(self, prd_name, prd_code, md5_value, oss_path, cdn_url, data: list):
        prd_list = data[0]
        detail = data[1] if len(data) > 1 else {}

        issue_ins = prd_name[:4]  # 发行机构

        risk_levels = {
            1: "低",
            2: "中低",
            3: "中",
            4: "中高",
            5: "高"
        }
        issue_ins_risk_rank = risk_levels.get(detail.get('risk_level', ''), '')  # 发行机构风险等级
        min_pur_amt = detail.get('pfirst_amt', '')  # 起购金额

        rule_anno = self.req_get_plus_rule_anno(prd_code)
        prod_spec_path = ''  # 产品说明书
        pur_rule = ''  # 购买规则
        rede_rule = ''  # 赎回规则

        doc_list = rule_anno.get('docList', [])
        for doc in doc_list:
            title = doc['title']
            url = doc['uri']
            if title == '产品说明书':
                file_name = f'产品说明书_{md5_value}.pdf'
                r = send_request.get(url)
                re_ret = re.findall(r"atob\(`(.*?)`", r.text)
                if re_ret:
                    prd_bytes = b64decode(re_ret[0])
                    result = data_insert_oss(self.path, prd_bytes, self.target_bank_name, file_name)
                    if result:
                        prod_spec_path, _ = result

        rules = rule_anno.get('ruleModule', {}).get('list', [])
        for rule in rules:
            title = rule['title']
            content = '\n'.join(rule.get('ruleList', []))
            if title == '转入规则':
                pur_rule = content.replace('{{productInfo.pfirst_amt | tranNumber}}', str(min_pur_amt))
            elif title == '转出规则':
                rede_rule = content

        data = {
            'inv_cycle': '',  # 投资周期
            'issue_ins': issue_ins,  # 发行机构
            'prod_feat': '',  # 产品特色
            'issue_ins_risk_rank': issue_ins_risk_rank,  # 发行机构风险等级
            'benchmark': '',  # 业绩比较基准
            'benchmark_calc': '',  # 业绩比较基准测算依据
            'prod_esta_date': '',  # 产品成立日
            'prod_intr_path': '',  # 产品介绍
            'qa': '',  # 常见问题
            'prod_spec_path': prod_spec_path,  # 产品说明书
            'min_pur_amt': min_pur_amt,  # 起购金额
            'incr_amt': '',  # 递增金额
            'pur_rule': pur_rule,  # 购买规则
            'pur_conf_rule': '',  # 购买确认规则
            'rede_rule': rede_rule,  # 赎回规则
            'rede_conf_rule': ''  # 赎回确认规则
        }

        return self.format_info('base', md5_value, oss_path, cdn_url, prd_name, prd_code, data)

    def req_get_his_pay_earn(self, prd_code: str = 'PP03312085') -> str:
        ret = ''
        url = 'https://wmt.aibank.com/app/api/wsp/access/getProductYieldList'
        data = {"version_no": "1", "transaction_code": "100279", "product_no": prd_code, "tag_value": "0", "start_position": 0,
                "query_number": 9999, "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}
        try:
            r = eval(self.wrap_request_post(url, data))
            pl = r['prd_benchmark_detail_list']
            ret = '\n'.join([f"{strftime('%Y-%m-%d', strptime(str(i['cycle_start']), '%Y%m%d'))}至{strftime('%Y-%m-%d', strptime(str(i['cycle_end']), '%Y%m%d'))}:{i['benchmark_show']}" for i in pl])
        except:
            pass

        return ret

    def req_get_sale_start_date(self, prd_code: str = 'PP03312010') -> str:
        """ 获取 bottomTip 购买路径1 """
        ret = ''
        url = 'https://wmt.aibank.com/app/api/wsp/access/productCommonCheck'
        # product_id 可能需要替换
        data = {"product_no": prd_code, "product_id": "150001", "taCode": "", "version_no": "1", "business_plat_no": "10000001",
                "transaction_code": "100035", "invest_source": "1", "invest_channel": "1", "req_channel": "1", "req_source": "1"}
        try:
            r = self.wrap_request_post(url, data)
            r = json.loads(r)
            check_list = r.get('check_list', [])
            for check in check_list:
                trans_type = check.get('trans_type')
                button_show = check.get('button_show')
                check_msg = check.get('check_msg')
                if trans_type in ['0', '1'] and button_show:
                    if '可购买' in check_msg:  # '2024-02-13 09:00 可购买'
                        ret = check_msg[:10]
        finally:
            return ret

    def parse_cycle(self, prd_name, prd_code, md5_value, oss_path, cdn_url, data: list):
        data_list = data[0]
        detail = data[1] if len(data) > 1 else {}

        # 路径1
        sale_start_date = self.req_get_sale_start_date(prd_code)  # 销售开始日(待售产品日期.路径1)
        if sale_start_date == '':
            sale_start_date = f'今日购买:{strftime("%Y-%m-%d")}'  # 路径2 今日购买：抓取日期(取当前日期)
        else:
            sale_start_date = f'今日购买:{sale_start_date}'

        sale_end_date = f"购买截止:{detail['buy_end_date']}" if detail.get('buy_end_date', '') else ''  # 销售结束日
        # 销售结束日小于当天日期，销售开始日置空
        if sale_end_date and sale_end_date.split(':')[-1] < strftime("%Y%m%d"):
            sale_start_date = ''
        conf_date = detail.get('buy_cycle_start_date', '')  # 确认日(确认份额)
        open_rede_start_date = open_rede_end_date = ''
        if detail.get('withdraw_close_time', '') != '160000':
            open_rede_start_date = detail.get('withdraw_start_date', '')  # 开放赎回开始日
            open_rede_end_date = detail.get('withdraw_end_date', '')  # 开放赎回结束日

        cycle_end_date = mat_date = ''  # 周期结束日/到期日
        product_open_form = detail.get('product_open_form', '')
        if product_open_form == 1:
            mat_date = detail.get('buy_cycle_end_date', '')
        elif product_open_form == 2:
            ...
        elif product_open_form == 3:
            e = '1' == detail.get('is_estimate_buy_cycle', '')
            n = '1' == detail.get('is_estimate_withdraw_cycle', '')
            cycle_end_date = detail.get('estimate_buy_adv_date', '') or detail.get('buy_cycle_end_date', '')
            conf_date = detail.get('estimate_buy_cfm_date', '') or detail.get('buy_cycle_start_date', '')  # 确认日

            buy_end_date = detail.get('estimate_buy_end_date', '') or detail.get('buy_end_date', '')
            sale_end_date = f"购买截止:{buy_end_date}" if buy_end_date else ''  # 销售结束日
        elif product_open_form == 4:
            n = '1' == detail.get('is_estimate_buy_cycle', '')
            t = '0' == detail.get('allow_change_ending', '')
            e = '0' == detail.get('allow_change_ending', '')
            if t:
                mat_date = detail.get('estimate_buy_adv_date', '') if n else detail.get('buy_cycle_end_date', '')
            else:
                cycle_end_date = detail.get('estimate_buy_adv_date', '') if n else detail.get('buy_cycle_end_date', '')

            if e:
                open_rede_start_date = open_rede_end_date = ''

        sale_stat = ''  # 销售状态
        surp_amt_sit = ''  # 剩余额度情况
        try:
            sale_status = data_list['product_common']['sale_status']
            if sale_start_date and sale_start_date.split(':')[-1] > strftime('%Y-%m-%d'):
                sale_stat = '不可购买'
            if sale_status == 1:
                sale_stat = surp_amt_sit = '已售罄'
                sale_start_date = ''
            elif sale_status == 2:
                sale_stat = '不可购买'  # '即将开售'
                sale_start_date = ''
            elif sale_status == 3:
                sale_stat = '立即购买'  # '在售'
        except:
            pass
        his_pay_earn = self.req_get_his_pay_earn(prd_code)  # 历史兑付收益

        data = {
            'sale_start_date': sale_start_date,  # 销售开始日
            'sale_end_date': sale_end_date,  # 销售结束日
            'conf_date': conf_date,  # 确认日(确认份额)
            'open_rede_start_date': open_rede_start_date,  # 开放赎回开始日
            'open_rede_end_date': open_rede_end_date,  # 开放赎回结束日
            'cycle_end_date': cycle_end_date,  # 周期结束日
            'mat_date': mat_date,  # 到期日
            'sale_stat': sale_stat,  # 销售状态
            'his_pay_earn': his_pay_earn,  # 历史兑付收益
            'surp_amt_sit': surp_amt_sit,  # 剩余额度情况
        }
        return self.format_info('cycle', md5_value, oss_path, cdn_url, prd_name, prd_code, data)

    def parse_cycle1(self, prd_name, prd_code, md5_value, oss_path, cdn_url, data: list):
        data = {
            'sale_start_date': '',  # 销售开始日
            'sale_end_date': '',  # 销售结束日
            'conf_date': '',  # 确认日(确认份额)
            'open_rede_start_date': '',  # 开放赎回开始日
            'open_rede_end_date': '',  # 开放赎回结束日
            'cycle_end_date': '',  # 周期结束日
            'mat_date': '',  # 到期日
            'sale_stat': '转入',  # 销售状态
            'his_pay_earn': '',  # 历史兑付收益
            'surp_amt_sit': '',  # 剩余额度情况
        }
        return self.format_info('cycle', md5_value, oss_path, cdn_url, prd_name, prd_code, data)

    def yield_data_update_his_net(self, data: dict, chg_and_anny: dict, his_yield_list: list) -> dict:
        """
        若年化更新日期等于当日日期，年化数据存入当日行情，否则存入历史行情；
        当需存入历史行情时，若年化更新日期包含在历史净值日期中，则年化数据与该条历史净值数据合并放在一起，若不一致，单独放在历史净值列表中
        data：待添加数据的行情字典
        chg_and_anny：涨跌幅与年化收益率
        his_yield_list：历史净值列表
        """
        now_int = int(datetime.now().strftime('%Y%m%d'))
        anny_date = chg_and_anny.get('his_net_value_date', '')
        if chg_and_anny:
            if anny_date < now_int:
                in_flag = 0
                for entry in his_yield_list:
                    if str(anny_date) == entry.get('his_net_value_date', ''):  # 年化更新日期包含在历史净值日期中，则年化数据与该条历史净值数据合并放在一起
                        for k, v in chg_and_anny.items():
                            if k == 'his_net_value_date':
                                continue
                            entry.update({k: v})
                        in_flag = 1
                if in_flag == 0:  # 单独放在历史净值列表中
                    his_yield_list.append(chg_and_anny)
                data.update({'his_yield_list': his_yield_list})

            elif anny_date == now_int:  # 若年化更新日期等于当日日期，年化数据存入当日行情
                data.update({'his_yield_list': his_yield_list})
                field_list = ['ann_yield_esta_to_day', 'chg_ratio_esta_to_day', 'ann_yield_1y', 'chg_ratio_1y', 'ann_yield_6m',
                              'chg_ratio_6m', 'ann_yield_3m', 'chg_ratio_3m', 'ann_yield_1m', 'chg_ratio_1m', 'chg_ratio_1w',
                              'ann_yield_1w']
                for key in field_list:
                    data[key] = chg_and_anny[key] if chg_and_anny.get(key) else ''
        else:  # 当chg_and_anny无数据时，仅添加历史净值数据
            data.update({'his_yield_list': his_yield_list})

        return data

    def parse_market(self, prd_name, prd_code, md5_value, oss_path, cdn_url, data: list):
        dicts = data[0]
        net_value_list = data[1] if len(data) > 1 else []
        chg_and_anny: dict = data[2] if len(data) > 2 else {}
        his_yield_list = [
            #     {
            #     'his_net_value_date': '',  # 净值日期
            #     'unit_net_value': '',  # 单位净值
            #     'ann_yield_7d': '',  # 七日年化收益率
            #     'ten_ths_earn': '',  # 万份收益
            #     'chg_ratio_1m': '',  # 近1月涨跌幅
            #     'chg_ratio_3m': '',  # 近3月涨跌幅
            #     'chg_ratio_6m': '',  # 近6月涨跌幅
            #     'chg_ratio_1y': '',  # 近1年涨跌幅
            #     'chg_ratio_esta_to_day': '',  # 成立以来涨跌幅
            #     'ann_yield_1m': '',  # 近1月年化收益率
            #     'ann_yield_3m': '',  # 近3月年化收益率
            #     'ann_yield_6m': '',  # 近6月年化收益率
            #     'ann_yield_1y': '',  # 近1年年化收益率
            #     'ann_yield_esta_to_day': '',  # 成立以来年化收益率
            # }
        ]

        for net_value in net_value_list:
            net_date = str(net_value.get('issue_date', ''))
            if self.spider_net_num == 'add':    # 抓增量
                # 判断净值日期是否在一个月内
                if not is_within_days(net_date, NET_DAY):
                    continue
            his_yield_list.append({
                'his_net_value_date': net_date,  # 净值日期
                'unit_net_value': str(net_value.get('net_asset_value', '')),  # 单位净值
                'accu_net_value': str(net_value.get('total_nav', '')),  # 单位净值
                'ann_yield_7d': net_value.get('ann_yield_7d', ''),  # 七日年化收益率
                'ten_ths_earn': net_value.get('ten_ths_earn', ''),  # 万份收益
            })

        # cleaned_data
        his_yield_list = [{k: v for k, v in entry.items() if v} for entry in his_yield_list]

        data = dict()
        # 判断涨跌幅与年化收益率的更新时间，来决定入历史还是当日
        data = self.yield_data_update_his_net(data, chg_and_anny, his_yield_list)

        # his_net_value_date = chg_and_anny.get('his_net_value_date')
        # is_add = False
        # for his_yield in his_yield_list:
        #     if his_net_value_date and his_yield['his_net_value_date'] == his_net_value_date:
        #         his_yield.update(chg_and_anny)
        #         is_add = True
        # not is_add and his_yield_list.append(chg_and_anny)

        return self.format_info('market', md5_value, oss_path, cdn_url, prd_name, prd_code, data)

    def parse_anno(self, prd_name, prd_code, md5_value, oss_path, cdn_url, data: list):
        anno_list = []
        annos = len(data) > 1 and data[1] or []
        if not annos:
            return True
        # 判断抓公告文件的全量还是增量
        annos = annos if self.spider_ann_num == 'all' else annos if ANN_NUM >= 1000 else annos[:ANN_NUM]
        for anno in annos:
            title = anno.get('title', '')
            url = anno.get('uri', '')
            date = anno.get('date', '')
            if not title or not url:
                continue
            r = send_request.get(url)
            if not r:
                continue
            pdf_data = re.findall(r"atob\(`(.*?)`", r.text)
            if pdf_data:
                prd_bytes = b64decode(pdf_data[0])
                file_name = f'{title}.pdf'
            else:
                png_data = re.findall(r'<img src="(.*)" /><', r.text)[0]
                if png_data.startswith('data:image/jpeg;base64,'):
                    prd_str = png_data.split(',')[1]
                    prd_bytes = b64decode(prd_str)
                elif png_data.startswith('data:image/png;base64,'):
                    prd_str = png_data.split(',')[1]
                    prd_bytes = b64decode(prd_str)
                else:
                    continue
                file_name = f'{title}.png'
            anno_oss_path, _ = data_insert_oss(self.path, prd_bytes, self.target_bank_name, file_name)

            anno_list.append({  # 公告列表
                'anno_title': title,  # 公告标题
                'anno_date': date,  # 公告日期
                'anno_file_path': anno_oss_path,  # 公告文件(存储为OSS附件路径）
            })

        return self.format_info('anno', md5_value, oss_path, cdn_url, prd_name, prd_code, {"anno_list": anno_list})

    def parse_tag(self, prd_name, prd_code, md5_value, oss_path, cdn_url, data: list):
        dicts = data[0]
        d = data[1] if len(data) > 1 else {}
        # todo: 路径1:产品列表-按产品 官方变动取消了
        # todo: 路径2:财富-稳健投资-灵活取用 官方变动取消了
        # todo: 路径4：财富-滚动推荐 抓不了

        # tag_list = [{'plate': '稳健投资', 'prod_tag': ','.join([i['label_desc'] for i in d.get('product_labels', [])])}]
        if dicts['product_common']['product_labels']:
            tag_list = [{'plate': '全部', 'prod_tag': ','.join([i['label_desc'] for i in dicts['product_common']['product_labels']])}]
        else:
            tag_list = [{'plate': '全部', 'prod_tag': ''}]
        print(tag_list)
        print(self.format_info('tag', md5_value, oss_path, cdn_url, prd_name, prd_code, {'tag_list': tag_list}))
        return self.format_info('tag', md5_value, oss_path, cdn_url, prd_name, prd_code, {'tag_list': tag_list})

    def parse_rate(self, prd_name, prd_code, md5_value, oss_path, cdn_url, data: list):
        dicts = data[0]

        fee_rate_list = [{
            'fee_rate_type': '购买费率',  # 费率类型
            'fee_rate': ''  # 费率
        }, {
            'fee_rate_type': '赎回费率',  # 费率类型
            'fee_rate': ''  # 费率
        }]
        return self.format_info('rate', md5_value, oss_path, cdn_url, prd_name, prd_code, {'fee_rate_list': fee_rate_list})

    def parse_comb(self, prd_name, prd_code, md5_value, oss_path, cdn_url, data: list):
        dicts = data[0]
        ann_yield_7d = f"{round(dicts['seven_rate'] * 100, 6)}" if dicts.get('seven_rate', '') else ''  # 近七日年化收益率

        data = {
            'comb_prod_name': '钱包plus',  # 组合名称
            'single_prod_name': prd_name,  # 单只产品名称
            'ann_yield_7d': ann_yield_7d,  # 近七日年化收益率
        }
        return self.format_info('comb', md5_value, oss_path, cdn_url, '', '', data)

    @AppSpider.catch_the_error
    def spider_data(self, data):

        def product_basic_info():
            self.base('base', data)
    
        def product_cycle_info():
            self.base('cycle', data)
    
        def product_market_info():
            self.base('market', data)
    
        def product_tags_info():
            self.base('tag', data)
    
        def product_announcement_info():
            self.base('anno', data)
    
        def product_comb_info():
            self.base('comb', data)
    
        def product_rate_info():
            self.base('rate', data)

        # 爬虫调用
        if self.spider_table == 'all':
            product_basic_info()
            product_cycle_info()
            product_market_info()
            product_tags_info()
            product_comb_info()
            product_rate_info()
            product_announcement_info()
        elif self.spider_table == 'product_basic_info':
            product_basic_info()
        elif self.spider_table == 'product_cycle_info':
            product_cycle_info()
        elif self.spider_table == 'product_market_info':
            product_market_info()
        elif self.spider_table == 'product_tags_info':
            product_tags_info()
        elif self.spider_table == 'product_comb_info':
            product_comb_info()
        elif self.spider_table == 'product_rate_info':
            product_rate_info()
        elif self.spider_table == 'product_announcement_info':
            try:
                self.mutex.acquire()
                product_announcement_info()
            except Exception as e:
                self.logger.error(e)
                # 应该是请求失败
                return
            finally:
                self.mutex.release()

    def run(self, bool_oss: bool = False, max_workers: int = 16, spider_table: str = 'product_tags_info', spider_ann_num: str = 'add',
            spider_net_num: str = 'add'):
        """
        bool_oss: 表示数据是否从oss读取
        max_workers: 表示线程数
        spider_ann_num: 表示指定抓"公告文件"增量还是全量，参数add表示增量默认抓取前5条公告，参数all表示全量
        spider_net_num: 表示指定抓"净值"增量还是全量，参数add表示增量默认抓取30天内的数据，参数all表示全量
        spider_table: 表示指定抓什么表
            默认抓取所有表，需抓取指定表，可以将spider_table修改成指定的表名
            all：所有表，
            product_basic_info: 基础表，
            product_cycle_info： 期间状态表，
            product_market_info：净值分红行情表，
            product_tags_info：标签表，
            product_comb_info
            product_announcement_info：公告表，
            product_rate_info：费率表
        """
        prds_list = []
        prd_list = self.get_prd_list()  # 精选理财
        prds_list.extend(prd_list)
        plus_list = self.get_wallet_plus_list()  # 钱包plus
        prds_list.extend(plus_list)
        self.spider_table = spider_table

        # 调试
        debug_f = 0
        if debug_f:
            prds_list = [i for i in prds_list if i.get('product_common', {}).get('product_no') in ['PP03312241']]
            self.spider_table = 'product_market_info'
            max_workers = 1

        self.spider_ann_num = spider_ann_num
        self.spider_net_num = spider_net_num
        self.thread_pool(self.spider_data, prds_list, max_workers)
        return self.task_status()


if __name__ == '__main__':
    a = BaiXinBank_()
    if sys.gettrace() is not None:
        a.run(max_workers=12)
    else:
        a.run()
