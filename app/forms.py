from django import forms

class QuickSearchForm(forms.Form):
    
    domain 			= forms.CharField(
    	label='domaine :',
    	max_length=100,
    	widget=forms.TextInput(attrs={'class': 'form-control'}),
    	required=True,
    	)

class SearchForm(forms.Form):
    
    file = forms.FileField(label='Liste des domaines',
    	required=True,)

class ControleContinuForm(forms.Form):
	domains_file 	= forms.FileField(
    	label='Liste des domaines',
    	required=True,
    	)

class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=50)
    file = forms.FileField()

# class DocumentForm(forms.Form):
# 	docfile = forms.FileField(label='Selectionner un fichier',
#                           help_text='Taille max.: 42 megabytes')


"""
file 	= forms.FileField(
    	label='Liste des domaines',
    	required=True,
    	)
"""

"""
<label>Liste des contacts</label> 
<div class="custom-file">
  <input id="filecontacts" name="filecontacts" type="file" class="custom-file-input"/>
  <label class="custom-file-label" for="filecontacts">Choisir un fichier</label>
</div>
"""
