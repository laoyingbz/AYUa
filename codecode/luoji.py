# 假设以下是 res_data 的示例数据
res_data = {
    'status': 'ctive',
    'priority': 0,
    'category': 'software',
    'quickRedeemDamtUp': '10000.00'
}

tag_list = []

# 根据不同条件添加标签
if res_data['status'] == 'active':
    tag_list.append('active')
elif res_data['priority'] and res_data['priority'] > 1:
    tag_list.append('high_priority')
elif res_data['category'] == 'software':
    tag_list.append('software_product')
elif res_data['quickRedeemDamtUp'] and res_data[
        'quickRedeemDamtUp'] == "10000.00":
    tag_list.append('quick_redeem')

print(tag_list)
print(11)
