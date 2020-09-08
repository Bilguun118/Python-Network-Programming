#Ашигласан Сангууд
import librouteros as ros   
from librouteros import token
import pandas as pd 
import json 
import ssl  

#Creating Class
#Класс үүсгэх
class TunnelMonitoring(object):
	
    #Байгуулагч функц
	def __init__(self, ip_address, port, user_in, passw, key):

		self.ip_address = ip_address
		self.port = port 
		self.username = user_in
		self.password = passw 
		self.key = key

	#Connecting to router
    #Сүлжээний замчлагч төхөөрөмжтэй холбогдох метод
	def nonencrypt_connecting_router(self):

		api = ros.connect(username=self.username, 
			password=self.password, 
			host=self.ip_address, 
			port=self.port
			)
		return api

	#getter функц
	def getter_ip(self):
		return self.ip_address, self.port

	#setter функц
	def setter_ip(self,new_ip_address, new_port):
		self.ip_address = new_ip_address
		self.port = new_port

	#connecting_to_router_with_encryption
    # SSL нууцлалтай сүлжээний төхөөрөмжид холбогдох	
	def connecting_with_ssl(self, user_in, passw, ip_address, port_number_2):

		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.set_ciphers('ADH:@SECLEVEL=0')
		api = ros.connect(username=user_in,
			password=self.password,
			host=self.ip_address,
			ssl_wraper=ctx.wrap_socket,
			login_method=token,
			port=self.port
			) 
		return api

	#Getting output of router tunnel connection in json format 
    #Замчлагч төхөөрөмжөөс өгөгдлийг хүлээн авч json format-руу хөрвүүлэх 
	def getting_output_as_json(self, api):

		info = api(cmd="/ip/ipsec/policy/print")
		output_in_dic = json.dumps(info, indent=3)
		return output_in_dic

	#getting output data using panda
	#Ipsec Used in example 
    #Python Panda сангийн тусламжтайгаар өгөгдлийг хүснэгт байдлаар харах PandaDataFrame - руу хөрвүүлэх
	def getting_output_as_panda(self, api):
		
		new_data = api.path('ip', 'ipsec', 'policy')
		output_data = pd.DataFrame.from_dict(new_data)
		output_data.drop(output_data.columns.difference(['.id',
			'proposal',
			'src-address', 
			'dst-address', 
			'ph2-count', 
			'ph2-state']), 
		axis=1, 
		inplace=True
		)
		return output_data
