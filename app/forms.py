from django import forms

class QuickSearchForm(forms.Form):
    
    domain = forms.CharField(
    	label='domain',
    	max_length=100,
    	widget=forms.TextInput(attrs={'class': 'form-control'}),
    	required=True,
    	)



