# STEGPASS
 STEGPASS - A Steganography-based Password Manager

# TO SET UP
 To set up the program: 
    pip install -r requirements.txt
 
 There was a report of missing imports for cv2 (this is the opencv-python package in requirements.txt).
 If this is the case for you, a virtual environment should solve the issue.
 
 1. To set up the program using virtual environment:
    python -m venv env
 2. Then activate the virtual environment, in a cmd.exe terminal:
    env\scripts\Activate.bat
 3. Finally install the dependencies as per usual:
    pip install -r requirements.txt

# TO RUN
 To run the program:
 python stegpass -e -> Saving a new password
 python stegpass -d -> Extracting a saved password