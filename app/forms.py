from django import forms

class QuickSearchForm(forms.Form):
  
    domain = forms.CharField(
        label='domaine :',
        max_length=100,
        widget=forms.TextInput(attrs={'class': 'form-control'}),
        required=True,
        )

class CreateClientForm(forms.Form):
    name = forms.CharField(
    	label='nom du client',
    	max_length=100,
    	widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'nom du client'}),
    	required=True,
    	)

    description = forms.CharField(
        label='description',
    	max_length=500,
    	widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'description'}),
    	required=False,
    	)
    logoname = forms.CharField(
    	label='nom du logo',
    	max_length=100,
    	widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'nom du logo (format carré)'}),
    	required=False,
    	)

