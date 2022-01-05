class Result:

	app = ''
	url = ''
	source = ''
	destination = ''
	type = ''
	info = ''
	flowContent = ''
	log = ''
	logFull = ''

	def __init__(self, flow):
		self.app = flow.app
		self.url = flow.get_url()
		self.source = flow.get_host()
		self.destination = flow.get_destination()
		self.type = flow.get_type()
		self.info = flow.get_user_agent()
		self.flowContent = flow.raw_flow.request.content
		self.log = flow.get_source()
		self.destination = flow.get_destination()
		self.type = flow.get_type()
		self.logFull = self.log + str(self.flowContent)

	def get_app(self):
		return self.app

	def get_source(self):
		return self.source

	def get_destination(self):
		return self.destination

	def get_type(self):
		return self.type

	def get_info(self):
		return str(self.info)

	def get_flow_content(self):
		return self.flowContent

	def get_log(self):
		return self.log

	def get_log_full(self):
		return self.logFull

	def get_url(self):
		return self.url
