import base64
import mimetypes
import os

from django.core.urlresolvers import reverse
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.views.decorators.csrf import csrf_exempt


## 01 - Injection Attacks

def norm(s):
    return s.strip().replace(' ', '').lower()


def sql(request):
  ## The lines 25-29 below this comment allow potential sql injection to be entered and allow 
  # malicious sql queries to be passed through and executed.
  # Solution to help prevent this would be use a parameterized query. The query uses 
  # placeholders for parameters and the parameter values are supplied at execution time. This 
  # doesn't entirely stop sql injection attacks if the stored procedures executing the query 
  # concatenate the queries and data, or executes the query utilizing EXECUTE IMMEDIATELY or 
  # exec()
    solution_sql = ("SELECT id from Users where first_name = ''; "
                    "DROP TABLE Users;--';")
    expected_sql = "'; DROP TABLE Users;--"

    name = request.POST['name'] if request.method == 'POST' else ''
    correct = (norm(name) == norm(expected_sql))

    return render(request, 'vulnerable/injection/sql.html',
            {'name': name, 'correct': correct, 'solution_sql': solution_sql})


def file_access(request):
    msg = request.GET.get('msg', '')
    return render(request, 'vulnerable/injection/file_access.html',
            {'msg': msg})


def user_pic(request):
    """A view that is vulnerable to malicious file access."""

    ## The line right below sets a partial path to the file it's displaying on the website. 
    # Saavy and malicious people can use this to gain access to other and even more sensitive 
    # files on the server. This type of attack is typically called Path Traversal.
    # In this specific situation, I would suggest that users cannot supply all parts of the 
    # path by surrounding whatever the user might enter with the path code.
    # Another solution would be to validate the user's input by only accepting known good and 
    # not sanitizing the data.
    # Use chrooted jails and code access policies to restrict where the files can be obtained
    base_path = os.path.join(os.path.dirname(__file__), '../../badguys/static/images')
    filename = request.GET.get('p')

    try:
        data = open(os.path.join(base_path, filename), 'rb').read()
    except IOError:
        if filename.startswith('/'):
            msg = "That was worth trying, but won't always work."
        elif filename.startswith('..'):
            msg = "You're on the right track..."
        else:
            msg = "Keep trying..."
        return render(request, 'vulnerable/injection/file_access.html',
                {'msg': msg})

    return HttpResponse(data, content_type=mimetypes.guess_type(filename)[0])


def code_execution(request):
    data = ''
    msg = ''
    first_name = ''
    if request.method == 'POST':

        # Clear out a previous success to reset the exercise
        try:
            os.unlink('p0wned.txt')
        except:
            # this is bad practice to silently ignore exceptions
            # instead use try_exept_pass:
            #               check_typed_exception: True
            pass

        first_name = request.POST.get('first_name', '')

        ## these exec commands lack proper input validation and allow dynamic evaluation of 
        # user input in a dangerous way. Hackers could use the exec() command to execute 
        # python code from the string provided by the first_name field. Instead of the 
        # intended values of a first name, hackers could provide the application with 
        # something more maliscious instead. Exec is similar to Eval in Python.
        # Ways to protect against RCE from exec and eval:
        # 1) restrict access to global and local variables by passing dictionaries as the 
        #    second and third arguments to eval/exec.
        # 2) Override _builtins_ to restrict access to built-ins
        # 3) Add runtime assertions in order to evaluate a given expression and either moves 
        #    along or raises an AssertionError
        try:
            # Try it the Python 3 way...
            exec(base64.decodestring(bytes(first_name, 'ascii')))
        except TypeError:
            # Try it the Python 2 way...
            try:
                exec(base64.decodestring(first_name))
            except:
              # this is bad practice to silently ignore exceptions
              # instead use try_exept_pass:
              #               check_typed_exception: True
                pass
        except:
          # this is bad practice to silently ignore exceptions
          # instead use try_exept_pass:
          #               check_typed_exception: True
            pass

        # Check to see if the attack was successful
        try:
            data = open('p0wned.txt').read()
        except IOError:
            data = ''

    return render(request, 'vulnerable/injection/code_execution.html',
            {'first_name': request.POST.get('first_name', ''), 'data': data})


## 02 - Broken Authentication & Session Management


## 03 - XSS
## Content security policies can be used to help mitigate against XSS attacks.
# In addition to whitelisting specific domains, CSPs can also specify nonces and hashes so 
# that if the nonce or hash does not match the value specified in the directive, the script 
# will not excecute.

## Stored XSS attack - The malicious script comes from the website's database.
def xss_form(request):
    env = {'qs': request.GET.get('qs', 'hello')}
    response = render(request, 'vulnerable/xss/form.html', env)
    response.set_cookie(key='monster', value='omnomnomnomnom!')
    return response

## Reflected XSS - where the script comes from the current HTTP request.
def xss_path(request, path='default'):
    env = {'path': path}
    return render(request, 'vulnerable/xss/path.html', env)

## DOM-based XSS - vulnerability exists on client-side code rather than server-side.
def xss_query(request):
    env = {'qs': request.GET.get('qs', 'hello')}
    return render(request, 'vulnerable/xss/query.html', env)


## 04 - Insecure Direct Object References

## Rather than use easy to follow identifiers for users, it is better to used salted hashed 
# identifiers, so when the identifiers are listed on the URL, it is more difficult to 
# enumerate the identifier and access other user accounts.
users = {
    '1': {
        'name': 'Foo',
        'email': 'foo@example.com',
        'admin': False,
    },
    '2': {
        'name': 'Bar',
        'email': 'bar@example.com',
        'admin': True,
    }
}

def dor_user_profile(request, userid=None):
    env = {}
    # this is where we could salt and hash the userid
    user_data = users.get(userid)

    if request.method == 'POST':
        user_data['name'] = request.POST.get('name') or user_data['name']
        user_data['email'] = request.POST.get('email') or user_data['email']
        env['updated'] = True

    env['user_data'] = user_data
    env['user_id'] = userid
    return render(request, 'vulnerable/direct_object_references/profile.html', env)

## 05 - Security Misconfiguration

## To protect from this, server hardening best practices should be in place. These include: 
# managing server access, minimizing the external footprint, patch vulnerabilities, minimize 
# the attack surface, restrict admin access, know what's happening, minimize user access 
# permissions, and establish communications.

def boom(request):
    raise Exception('boom')


## 06 - Sensitive Data Exposure

## Most databases these days allow you to ecrypt the data at rest, which is highly suggested 
# to protect client data from malicious attacks/attackers. Encrypting data in transit (by 
# posting data over HTTPS rather than HTTP or using GPG/PGP encryption for transmitting files 
# to SFTP or secure file sharing sites). Limiting who has access to sensitive data will also 
# help limit leaked PII. Maintaining secure and guarded backups will also help mitigate and 
# reduce losses from attacks such as ransomware attacks. Making sure that the web application 
# only supports the latest ciphers will also help reduce the risk of vulnerabilities accessible 
# by browsers, i.e. TLS 1.3 only vs 1.0+. 

def exposure_login(request):
    return redirect('exposure')


## 07 - Missing Function Level Access Control

## It's highly important to have access controls on user accounts to prevent users from easily 
# accessing other parts of the site they are not supposed to access, such as admin access when 
# they don't have admin priveleges. Best practice is to have a deny all type of access for all 
# user accounts and then have flags to open access to certain pages. This way, it will prevent 
# unauthorized access to pages in the web application. Special/hidden URLs or APIs are not the 
# way to secure access.

def missing_access_control(request):
    env = {}
    if request.GET.get('action') == 'admin':
        return render(request, 'vulnerable/access_control/admin.html', env)
    return render(request, 'vulnerable/access_control/non_admin.html', env)


## 08 - CSRF

@csrf_exempt
def csrf_image(request):
    env = {'qs': request.GET.get('qs', '')}
    return render(request, 'vulnerable/csrf/image.html', env)


## 09 - Using Known Vulnerable Components
# No exercise, just discussion?

## If the libraries/frameworks/software modules aren't being used, remove them from the code. 
# If they are, then these need to be constantly updated to reduce the risk of vulnerabilities.

## 10 - Unvalidated Redirects & Forwards

def unvalidated_redirect(request):
    # there is no validation or method controls applied to verify the 'url' that is being 
    # passed. An attacker could use this vulnerability to redirect unsuspecting users to their 
    # own, malicious, site. Especially if people just take the time to look at the first part 
    # of the URL and see that it's a legitimate URL and not pay attention to the rest of the 
    # URL that has the redirect.
    url = request.GET.get('url')
    return redirect(url)

def unvalidated_forward(request):
    # In this exercise, it's basically the same as #7 in that the attacker can change the URL 
    # to forward them to another part of the site they do not have access, such as an admin 
    # page. To remediate this, the OWASP site has bullet points that can be taken to mitigate 
    # these kinds of attacks. https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
    #   Avoid using redirects and forwards
    #   Don't allow the URL as user input for the destination
    #   When possible, authenticate the user in a way like using SSO tokens to send users to 
    #   the appropriate page.
    forward = request.GET.get('fwd')
    function = globals().get(forward)

    if function:
        return function(request)

    env = {'fwd': forward}
    return render(request, 'vulnerable/redirects/forward_failed.html', env)

def admin(request):
    return render(request, 'vulnerable/redirects/admin.html', {})


