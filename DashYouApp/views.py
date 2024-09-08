#views.py
from django.contrib.auth import authenticate, login
from django.shortcuts import redirect, render, get_object_or_404
from .models import Project, Pipeline, Service
from .models import Admin3s
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
import requests
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from jenkinsapi.jenkins import Jenkins
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from django.contrib.auth import logout
from django.http import HttpResponseRedirect

@login_required
def update_profile(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')
        role = request.POST.get('role')
        
        user = request.user
        user.email = email
        user.username = username
        user.save()
        
        messages.success(request, 'Your profile has been updated successfully.')
        return redirect('developper')
    
    return render(request, 'developper.html')

from django.contrib.auth import authenticate

@login_required
def update_password(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
            return redirect('change_password')
        
        user = authenticate(username=request.user.username, password=current_password)
        if user is not None:
            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password has been changed successfully.')
            return redirect('developper')
        else:
            messages.error(request, 'Current password is incorrect.')
    
    return render(request, 'developper.html')



from django.contrib.auth import authenticate

@login_required
def update_passwordpip(request):
    if request.method == 'POST':
        current_password = request.POST.get('current_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')
        
        if new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
            return redirect('change_password')
        
        user = authenticate(username=request.user.username, password=current_password)
        if user is not None:
            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Your password has been changed successfully.')
            return redirect('pipeline_page')
        else:
            messages.error(request, 'Current password is incorrect.')
    
    return render(request, 'pipeline_page.html')


@login_required
def update_profilepip(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        username = request.POST.get('username')
        
        user = request.user
        user.email = email
        user.username = username
        user.role = role
        
        messages.success(request, 'Your profile has been updated successfully.')
        return redirect('pipeline_page')
    
    return render(request, 'pipeline_page.html')

def authentication(request):
    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'login':
            username = request.POST.get('login_username')
            password = request.POST.get('login_password')
            
            user = authenticate(request, username=username, password=password)
            if user is not None:
                login(request, user)
                
                # Redirect based on user role
                if user.role == 'developer':
                    return redirect('developper')
                elif user.role == 'devops':
                    return redirect('pipeline_page')
                elif user.role == 'supervisor':
                    return redirect('supervisor')    
                elif user.role == 'admin':
                    return redirect('adminpage')    
                else:
                    return HttpResponse('Unauthorized', status=401)  # Handle unauthorized roles if needed
            else:
                return render(request, 'login.html', {'error': 'Invalid username or password'})

    return render(request, 'login.html')

def list_users(request):
    users = Admin3s.objects.all()
    return render(request, 'list_users.html', {'users': users})


def developper(request):
    if request.method == 'POST':
        if 'add_project' in request.POST:
            name = request.POST.get('name')
            description = request.POST.get('description')
            github_url = request.POST.get('github_url')
            languages = request.POST.get('languages')
            status = request.POST.get('status')

            Project.objects.create(
                name=name,
                description=description,
                github_url=github_url,
                languages=languages,
                status=status,
                user=request.user
            )
            return redirect('developper')  # Redirection vers la page d'accueil

        elif 'update_project' in request.POST:
            project_id = request.POST.get('project_id')
            project = get_object_or_404(Project, id=project_id)
            project.name = request.POST.get('name')
            project.description = request.POST.get('description')
            project.github_url = request.POST.get('github_url')
            project.languages = request.POST.get('languages')
            project.status = request.POST.get('status')
            project.save()

            return redirect('developper')  # Redirection vers la page d'accueil

        elif 'delete_project' in request.POST:
            project_id = request.POST.get('project_id')
            project = get_object_or_404(Project, id=project_id)
            if project.user == request.user or request.user.is_superuser:
                project.delete()

            return redirect('developper')  # Redirection vers la page d'accueil

    services = Service.objects.filter(role='developer')
    projects = Project.objects.all()
    
    return render(request, 'developper.html', {
        'projects': projects,
        'services': services  # Passez les services filtrés au template
    })

def supervisor(request):
    if request.method == 'POST':
        if 'update_password' in request.POST:
            current_password = request.POST.get('current_password')
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('confirm_password')
            
            if new_password != confirm_password:
                messages.error(request, 'New passwords do not match.')
                return redirect('supervisor')
            
            user = authenticate(username=request.user.username, password=current_password)
            if user is not None:
                user.set_password(new_password)
                user.save()
                update_session_auth_hash(request, user)
                messages.success(request, 'Your password has been changed successfully.')
                return redirect('supervisor')
            else:
                messages.error(request, 'Current password is incorrect.')
        
        elif 'update_profile' in request.POST:
            email = request.POST.get('email')
            username = request.POST.get('username')
            
            user = request.user
            user.email = email
            user.username = username
            user.save()
            
            messages.success(request, 'Your profile has been updated successfully.')
            return redirect('supervisor')
    services = Service.objects.filter(role='supervisor')

    return render(request, 'supervisor.html',{'services':services})



from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.utils.html import escape
import requests
import xml.etree.ElementTree as ET
from xml.sax import saxutils
import time

def extract_script_from_jenkinsfile(xml_content):
    """Extract the pipeline script from Jenkinsfile XML."""
    try:
        root = ET.fromstring(xml_content)
        script_element = root.find(".//script")
        if script_element is not None:
            return script_element.text.strip()
    except ET.ParseError:
        return None
    return None

def pipeline_page(request):
    jenkins_url = 'https://d41b-197-26-40-53.ngrok-free.app'
    jenkins_user = 'younes'
    jenkins_token = '11a3480f35d3a1395e27c6de042c7d6ce2'
    projects = Project.objects.all()

    if not jenkins_user or not jenkins_token:
        return HttpResponse('Jenkins user or token is not set.')

    crumb_response = requests.get(f'{jenkins_url}/crumbIssuer/api/json', auth=(jenkins_user, jenkins_token))
    if crumb_response.status_code != 200:
        return HttpResponse('Failed to fetch crumb: 401 Unauthorized. Check your credentials.')
    
    crumb = crumb_response.json().get('crumb')
    headers = {
        'Content-Type': 'application/xml',
        'Jenkins-Crumb': crumb
    }

    response = requests.get(f'{jenkins_url}/api/json?tree=jobs[name,url]', auth=(jenkins_user, jenkins_token))
    if response.status_code != 200:
        return HttpResponse(f'Failed to fetch pipelines: {response.status_code} {response.text}')
    
    pipelines = response.json().get('jobs', [])

    pipeline_details = None
    build_logs = None
    
    if request.method == 'POST':
        if 'details' in request.POST:
            pipeline_url = request.POST.get('pipeline_url')

            if not pipeline_url:
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': 'Pipeline URL is required.'
                })

            jenkinsfile_response = requests.get(f'{pipeline_url}/config.xml', auth=(jenkins_user, jenkins_token))
            if jenkinsfile_response.status_code != 200:
                return HttpResponse(f'Failed to fetch Jenkinsfile: {jenkinsfile_response.status_code} {jenkinsfile_response.text}')

            jenkinsfile_content = jenkinsfile_response.text
            pipeline_name = pipeline_url.split('/')[-1]

            pipeline_script = extract_script_from_jenkinsfile(jenkinsfile_content)

            pipeline_details = {
                'name': pipeline_name,
                'jenkins_file': escape(pipeline_script),
                'url': pipeline_url
            }

        elif 'add_pipeline' in request.POST:
            pipeline_name = request.POST.get('name')
            jenkins_file = request.POST.get('jenkins_file')

            if not pipeline_name or not jenkins_file:
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': 'Pipeline name and Jenkinsfile content are required.'
                })

            jenkins_file = f"""
            <flow-definition plugin="workflow-job@2.40">
              <description></description>
              <keepDependencies>false</keepDependencies>
              <properties/>
              <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps@2.92">
                <script>{saxutils.escape(jenkins_file)}</script>
                <sandbox>true</sandbox>
              </definition>
              <triggers/>
              <disabled>false</disabled>
            </flow-definition>
            """

            create_response = requests.post(
                f'{jenkins_url}/createItem?name={pipeline_name}',
                data=jenkins_file,
                headers=headers,
                auth=(jenkins_user, jenkins_token)
            )

            if create_response.status_code == 200:
                return redirect('pipeline_page')
            else:
                error_message = f'Failed to create pipeline: {create_response.status_code} {create_response.text}'
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': error_message
                })

        elif 'modify_pipeline' in request.POST:
            pipeline_url = request.POST.get('pipeline_url')
            modified_script = request.POST.get('jenkins_file')

            if not pipeline_url:
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': 'Pipeline URL is required.'
                })

            # Mise à jour du contenu du Jenkinsfile
            modify_response = requests.post(
                f'{pipeline_url}/config.xml',
                data=f"""<?xml version='1.1' encoding='UTF-8'?>
        <flow-definition plugin="workflow-job@1400.v7fd111b_ec82f">
        <actions>
            <org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobAction plugin="pipeline-model-definition@2.2198.v41dd8ef6dd56"/>
            <org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobPropertyTrackerAction plugin="pipeline-model-definition@2.2198.v41dd8ef6dd56">
            <jobProperties/>
            <triggers/>
            <parameters/>
            <options/>
            </org.jenkinsci.plugins.pipeline.modeldefinition.actions.DeclarativeJobPropertyTrackerAction>
        </actions>
        <description></description>
        <keepDependencies>false</keepDependencies>
        <properties>
            <hudson.plugins.jira.JiraProjectProperty plugin="jira@3.13"/>
        </properties>
        <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps@3894.vd0f0248b_a_fc4">
            <script>{modified_script}</script>
            <sandbox>true</sandbox>
        </definition>
        <triggers/>
        <disabled>false</disabled>
        </flow-definition>""",
                auth=(jenkins_user, jenkins_token),
                headers={'Jenkins-Crumb': crumb, 'Content-Type': 'application/xml'}
            )

            if modify_response.status_code == 200:
                return redirect('pipeline_page')
            else:
                error_message = f'Failed to modify pipeline: {modify_response.status_code} {modify_response.text}'
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': error_message
                })

        elif 'delete_pipeline' in request.POST:
            pipeline_name = request.POST.get('pipeline_name')

            if not pipeline_name:
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': 'Pipeline name is required.'
                })

            # Find the pipeline URL by its name
            pipeline = next((p for p in pipelines if p['name'] == pipeline_name), None)
            if not pipeline:
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': 'Pipeline not found.'
                })

            # Delete pipeline
            delete_response = requests.post(
                f'{pipeline["url"]}/doDelete',
                auth=(jenkins_user, jenkins_token),
                headers={'Jenkins-Crumb': crumb}
            )

            if delete_response.status_code == 200:
                return redirect('pipeline_page')
            else:
                error_message = f'Failed to delete pipeline: {delete_response.status_code} {delete_response.text}'
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': error_message
                })

        elif 'build_now' in request.POST:
            pipeline_url = request.POST.get('pipeline_url')

            if not pipeline_url:
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': 'Pipeline URL is required.'
                })

            # Trigger the build
            build_response = requests.post(
                f'{pipeline_url}/build',
                auth=(jenkins_user, jenkins_token),
                headers={'Jenkins-Crumb': crumb}
            )

            if build_response.status_code == 201:
                # Get the queue URL
                queue_url = build_response.headers.get('Location')
                if not queue_url:
                    return render(request, 'pipeline_page.html', {
                        'pipelines': pipelines,
                        'error': 'Failed to obtain queue URL.'
                    })

                # Wait for the build to start and get the build URL
                build_url = None
                while True:
                    queue_response = requests.get(f'{queue_url}/api/json', auth=(jenkins_user, jenkins_token))
                    if queue_response.status_code == 200:
                        queue_data = queue_response.json()
                        if 'executable' in queue_data:
                            build_number = queue_data['executable']['number']
                            build_url = f"{pipeline_url}/{build_number}/api/json"
                            break
                    time.sleep(1)  # Wait 1 second before checking again

                # Poll for build completion and fetch logs
                build_logs = None
                build_status = None
                while True:
                    build_response = requests.get(build_url, auth=(jenkins_user, jenkins_token))
                    if build_response.status_code == 200:
                        build_data = build_response.json()
                        build_status = build_data.get('result', 'UNKNOWN')
                        if build_status != 'UNKNOWN':
                            # Fetch build logs
                            log_url = f"{pipeline_url}/{build_data['number']}/consoleText"
                            log_response = requests.get(log_url, auth=(jenkins_user, jenkins_token))
                            if log_response.status_code == 200:
                                build_logs = log_response.text
                            else:
                                build_logs = 'Failed to retrieve logs'
                            break
                    time.sleep(1)  # Wait 1 second before checking again

                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'build_logs': build_logs,
                    'build_status': build_status
                })
            else:
                error_message = f'Failed to trigger build: {build_response.status_code} {build_response.text}'
                return render(request, 'pipeline_page.html', {
                    'pipelines': pipelines,
                    'error': error_message
                })
    services = Service.objects.filter(role='devops')

        

    return render(request, 'pipeline_page.html', {
        'pipelines': pipelines,
        'pipeline_details': pipeline_details,
        'build_logs': build_logs,
        'projects':projects,
        'services':services
    })


from django.shortcuts import render
import requests

from django.http import JsonResponse

def jenkins_build_logs(request, pipeline_name):
    jenkins_url = 'https://d41b-197-26-40-53.ngrok-free.app'
    jenkins_user = 'younes'
    jenkins_token = '11a3480f35d3a1395e27c6de042c7d6ce2'

    build_url = f"{jenkins_url}/job/{pipeline_name}/lastBuild/api/json"
    
    build_logs = None
    build_status = None

    try:
        build_response = requests.get(build_url, auth=(jenkins_user, jenkins_token))
        if build_response.status_code == 200:
            build_data = build_response.json()
            build_status = build_data.get('result', 'UNKNOWN')

            if build_status != 'UNKNOWN':
                log_url = f"{jenkins_url}/job/{pipeline_name}/{build_data['number']}/consoleText"
                log_response = requests.get(log_url, auth=(jenkins_user, jenkins_token))
                if log_response.status_code == 200:
                    build_logs = log_response.text
                else:
                    build_logs = 'Failed to retrieve logs'
        else:
            build_logs = 'Failed to retrieve build details'

    except Exception as e:
        build_logs = f'Error occurred: {str(e)}'

    return JsonResponse({
        'pipeline_name': pipeline_name,
        'build_logs': build_logs,
        'build_status': build_status
    })



def adminpage(request):

    jenkins_url = 'https://d41b-197-26-40-53.ngrok-free.app'
    jenkins_user = 'younes'
    jenkins_token = '11a3480f35d3a1395e27c6de042c7d6ce2'
    projects = Project.objects.all()

    if not jenkins_user or not jenkins_token:
        return HttpResponse('Jenkins user or token is not set.')

    crumb_response = requests.get(f'{jenkins_url}/crumbIssuer/api/json', auth=(jenkins_user, jenkins_token))
    if crumb_response.status_code != 200:
        return HttpResponse('Failed to fetch crumb: 401 Unauthorized. Check your credentials.')
    
    crumb = crumb_response.json().get('crumb')
    headers = {
        'Content-Type': 'application/xml',
        'Jenkins-Crumb': crumb
    }

    response = requests.get(f'{jenkins_url}/api/json?tree=jobs[name,url]', auth=(jenkins_user, jenkins_token))
    if response.status_code != 200:
        return HttpResponse(f'Failed to fetch pipelines: {response.status_code} {response.text}')
    
    pipelines = response.json().get('jobs', [])
    users = Admin3s.objects.all()
    projects = Project.objects.all()

    
    if request.method == 'POST':
        if 'delete_user' in request.POST:
            user_id = request.POST.get('user_id')
            user = get_object_or_404(Admin3s, id=user_id)
            user.delete()
            return redirect('adminpage')  # Redirect to avoid form resubmission
        
        elif 'toggle_status' in request.POST:
            user_id = request.POST.get('user_id')
            user = get_object_or_404(Admin3s, id=user_id)
            user.is_active = not user.is_active
            user.save()
            return redirect('adminpage')  # Redirect to avoid form resubmission

        elif 'add_user' in request.POST:
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')

            role = request.POST.get('role')
            # On ignore la case "is_active", on la met à True par défaut
            user = Admin3s.objects.create_user(username=username, email=email, password=password, role=role)
            return redirect('adminpage')  # Redirect to avoid form resubmission

        if 'add_service' in request.POST:
            nom = request.POST.get('nom')
            image = request.FILES.get('image')  # Obtenir le fichier téléchargé
            url = request.POST.get('url')
            role = request.POST.get('role')
            # Créez une instance de Service
            Service.objects.create(nom=nom, image=image, url=url, role=role)
            return redirect('adminpage')  # Rediriger pour éviter la resoumission du formulaire

        elif 'delete_service' in request.POST:
            service_id = request.POST.get('service_id')
            service = get_object_or_404(Service, id=service_id)
            service.delete()
            return redirect('adminpage')    

    services = Service.objects.all()
    return render(request, 'adminpage.html', {
        'users': users,
        'projects': projects,
        'pipelines': pipelines,
        'services': services  # Passez les services au template
    })
        


def manage_services(request):
    if request.method == 'POST':
        # Ajouter un service
        if 'add_service' in request.POST:
            name = request.POST.get('service_name')  # Correspond au nom du champ dans le formulaire
            description = request.POST.get('service_description')  # Correspond au nom du champ dans le formulaire
            print("Received: name={name}, description={description}")
            if name:
                Admin3s.objects.create(name=name, description=description)
                messages.success(request, 'Service added successfully!')
            else:
                messages.error(request, 'Name is required!')

        # Supprimer un service
        elif 'delete_service' in request.POST:
            service_id = request.POST.get('service_id')
            service = get_object_or_404(Admin3s, id=service_id)
            service.delete()
            messages.success(request, 'Service deleted successfully!')

    # Afficher la liste des services
    services = Admin3s.objects.all()
    return render(request, 'adminpage.html', {'services':services})


def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/')


