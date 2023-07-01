
class SessionTimeoutMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if request.path != request.session.get('last_url') or request.method == 'POST' or request.path == 'GET':
            request.session.set_expiry(request.session.get_expiry_age())
            request.session['last_url'] = request.path        
        response = self.get_response(request)
        return response