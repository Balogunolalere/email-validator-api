import requests

headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.9',
    'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJpMm1EYmliOENoSUVEUkpSSlVlNGFJd1gwWFJydTlfODRpZk91a21jMG44In0.eyJleHAiOjE3NzA3NjgxMzIsImlhdCI6MTc3MDczMjEzMiwianRpIjoiOTMwNzNiMWEtZTAxYS00N2UzLWFmN2UtZGNkMDZkNmIwYjQyIiwiaXNzIjoiaHR0cHM6Ly9hdXRoLmdzZHMubmcvcmVhbG1zL2Jvb2tpbmctcHJvZCIsImF1ZCI6Im5vcm1hbC1jbGllbnQiLCJzdWIiOiI4NDllMjI4NS02NDIzLTRmYmMtODZkMC01M2ZjZGMwODZkNzgiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJub3JtYWwtY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjQ1MTg4NThhLThhY2MtNGQ5OS05ZDZjLTVlNzEzYzJkNjA5MCIsImFjciI6I…Yy00ZDk5LTlkNmMtNWU3MTNjMmQ2MDkwIiwiZW1haWxfdmVyaWZpZWQiOmZhbHNlLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJsb3JkYXJlZWxsb0BnbWFpbC5jb20iLCJlbWFpbCI6ImxvcmRhcmVlbGxvQGdtYWlsLmNvbSJ9.Om9RPtsKkqYxnDdyAS2xpCvl1sjiIQV7-dh_vNwOPZ6E_zXwlTmw-MMdnOF0cSo-8u2uXokZC8v71n2LUbM8Ep1CcLPxc0sP0uqQRWm5YaGaXUJl3VYXtjBDhsVlJ5csklYuwOMs2aLesRaCEmnkY-49z4A3dEqXR7fTkqdGSdJsu_z63oJ4rUnf8CypiK02NMKKmH0pYujS1Yf2KEWL4xhgUmVU3maNHEdF4pRmUrXQVyvXbiuRNZDotaPsYEnyQswz4VgTn5voTVnKzTD75KBTubjHpfLmIH5htph_oNn5SfvmvFPsAa_7kaWvuu4CEkUAtnbD6wUj-O7yPeGvdA', 
    # 'Accept-Encoding': 'gzip, deflate, br, zstd',
    'Access-Control-Request-Method': 'POST',
    'Access-Control-Request-Headers': 'authorization,content-type',
    'Referer': 'https://nrc.gsds.ng/',
    'Origin': 'https://nrc.gsds.ng',
    'Connection': 'keep-alive',
    'Sec-Fetch-Dest': 'empty',
    'Sec-Fetch-Mode': 'cors',
    'Sec-Fetch-Site': 'same-site',
    'DNT': '1',
    'Sec-GPC': '1',
    'Priority': 'u=4',
}

params = {
    'ninNumber': '35404838111',
}

response = requests.post('https://api.gsds.ng/cs/verify/verify-nin-details', params=params, headers=headers)

print(response.status_code)
print(response.headers)
print(response.text)