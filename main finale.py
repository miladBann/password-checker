import hashlib
import requests
from tkinter import Button, Canvas, Entry, Label, PhotoImage, Tk


GREY = "#e7e6e1"
WHITE = "#f7f6e7"
ORANNGE = "#f2a154"
BLACK = "#314e52"

#----------------------------------code & logic----------------------------------------#


symbols = ["!", "@", "#", "$", "%", "^", "&", "*", "/"]


def get_pass():
    password = entry.get()
    check_password(password)


def reset():
    answer1.config(text="")
    answer2.config(text="")
    answer3.config(text="")
    answer4.config(text="")
    final_answer.config(text="")
    semi_answer.config(text="")


def check_password(password):
    valid = True

    if len(password) < 8:
        valid = False
        answer1.config(
            text=f"the lenght should at least be 8 chars \n")
    if not any(char in symbols for char in password):
        valid = False
        answer2.config(
            text="it should have at least one symbol !,@,#,$,%,^,&,*")
    if not any(char.isdigit() for char in password):
        valid = False
        answer4.config(text="password should have at least on number")
    if not any(char.isupper() for char in password):
        valid = False
        answer3.config(
            text="password should have at least one upper case char")
    elif valid:
        answer1.config(text="looks good", font=("Impact", 12, "italic"))
        answer2.config(text="Password is Valid.")
        answer3.config(
            text="Checking the internet to see if this Password has ever")
        answer4.config(text="been leaked before")
        main(password)


def connect_to_API(semi_pass):
    url = 'https://api.pwnedpasswords.com/range/' + semi_pass
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            "Please check if the password is hashed correcrtly!")
    else:
        return res


def check_leak_count(hash, hash_to_check):
    hash = (line.split(":") for line in hash.text.splitlines())
    for h, count in hash:
        if h == hash_to_check:
            return count
    return 0


def hash_the_password(passed):
    hashed_pass = hashlib.sha1(passed.encode('utf-8')).hexdigest().upper()
    first5, rest = hashed_pass[:5], hashed_pass[5:]
    response = connect_to_API(first5)
    return check_leak_count(response, rest)


def main(password):
    count = hash_the_password(password)
    if count:
        semi_answer.config(text="Final Result:")
        final_answer.config(
            text=f"{password} has been found {count} times and shouldn't be used.")
    else:
        semi_answer.config(text="Final Result:")
        final_answer.config(
            text=f"{password} wasn't found and its safe to use.")
#----------------------------------solo checker screen----------------------------------------#


def solo_chcecker():
    def go_back():
        def get_pass():
            password = entry.get()
            check_password(password)

        def reset():
            answer1.config(text="")
            answer2.config(text="")
            answer3.config(text="")
            answer4.config(text="")
            final_answer.config(text="")
            semi_answer.config(text="")

        def check_password(password):
            valid = True

            if len(password) < 8:
                valid = False
                answer1.config(
                    text=f"the lenght should at least be 8 chars \n")
            if not any(char in symbols for char in password):
                valid = False
                answer2.config(
                    text="it should have at least one symbol !,@,#,$,%,^,&,*")
            if not any(char.isdigit() for char in password):
                valid = False
                answer4.config(text="password should have at least on number")
            if not any(char.isupper() for char in password):
                valid = False
                answer3.config(
                    text="password should have at least one upper case char")
            elif valid:
                answer1.config(text="looks good",
                               font=("Impact", 12, "italic"))
                answer2.config(text="Password is Valid.")
                answer3.config(
                    text="Checking the internet to see if this Password has ever")
                answer4.config(text="been leaked before")
                main(password)

        def connect_to_API(semi_pass):
            url = 'https://api.pwnedpasswords.com/range/' + semi_pass
            res = requests.get(url)
            if res.status_code != 200:
                raise RuntimeError(
                    "Please check if the password is hashed correcrtly!")
            else:
                return res

        def check_leak_count(hash, hash_to_check):
            hash = (line.split(":") for line in hash.text.splitlines())
            for h, count in hash:
                if h == hash_to_check:
                    return count
            return 0

        def hash_the_password(passed):
            hashed_pass = hashlib.sha1(
                passed.encode('utf-8')).hexdigest().upper()
            first5, rest = hashed_pass[:5], hashed_pass[5:]
            response = connect_to_API(first5)
            return check_leak_count(response, rest)

        def main(password):
            count = hash_the_password(password)
            if count:
                semi_answer.config(text="Final Result:")
                final_answer.config(
                    text=f"{password} has been found {count} times and shouldn't be used.")
            else:
                semi_answer.config(text="Final Result:")
                final_answer.config(
                    text=f"{password} wasn't found and its safe to use.")

        window.title("Secure Password")
        window.maxsize(width=510, height=600)
        window.config(bg=WHITE, padx=10, pady=10)

        # creating the canvas
        canvas = Canvas(width=450, height=600, highlightthickness=0, bg=WHITE)
        logo = PhotoImage(file="logo.png")
        canvas.create_image(350, 100, image=logo)
        canvas.grid(row=1, column=1)

        # the first label
        entry_label = Label(text="Secure your password Fast!",
                            font=("Impact", 15, "italic"), bg=WHITE, fg=BLACK)
        entry_label.place(x=20, y=170)

        # the question label
        questtion_label = Label(text="What is the Password you've been thinking about?", font=(
            "Impact", 15, "italic"), bg=WHITE, fg=BLACK)
        questtion_label.place(x=20, y=240)

        # the user input
        entry = Entry(width=30)
        entry.place(x=20, y=280)

        # the check button
        check_button = Button(text="Check Password", command=get_pass)
        check_button.place(x=240, y=275)

        # the reset button
        reset_button = Button(text="Reset", command=reset)
        reset_button.place(x=350, y=275)

        # Check your current passowrd button
        solo_chcek = Button(
            text="Check your current password", command=solo_chcecker)
        solo_chcek.place(x=20, y=20)

        # first stage checking answers label
        answer1 = Label(text="", font=(
            "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
        answer1.place(x=20, y=330)

        answer2 = Label(text="", font=(
            "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
        answer2.place(x=20, y=350)

        answer3 = Label(text="", font=(
            "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
        answer3.place(x=20, y=370)

        answer4 = Label(text="", font=(
            "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
        answer4.place(x=20, y=390)

        # before the final result
        semi_answer = Label(text="", font=(
            "Impact", 12, "italic"), bg=WHITE, fg=BLACK)
        semi_answer.place(x=20, y=440)

        # final stage checking label
        final_answer = Label(text="", font=(
            "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
        final_answer.place(x=20, y=460)

        window.mainloop()

    def get_pass2():
        password = entry.get()
        main2(password)

    def reset2():
        answer1.config(text="")
        answer2.config(text="")
        answer3.config(text="")
        answer4.config(text="")
        final_answer.config(text="")
        semi_answer.config(text="")

    def connect_to_API2(semi_pass):
        url = 'https://api.pwnedpasswords.com/range/' + semi_pass
        res = requests.get(url)
        if res.status_code != 200:
            raise RuntimeError(
                "Please check if the password is hashed correcrtly!")
        else:
            return res

    def check_leak_count2(hash, hash_to_check):
        hash = (line.split(":") for line in hash.text.splitlines())
        for h, count in hash:
            if h == hash_to_check:
                return count
        return 0

    def hash_the_password2(passed):
        hashed_pass = hashlib.sha1(passed.encode('utf-8')).hexdigest().upper()
        first5, rest = hashed_pass[:5], hashed_pass[5:]
        response = connect_to_API2(first5)
        return check_leak_count2(response, rest)

    def main2(password):
        count = hash_the_password2(password)
        if count:
            answer1.config(text="let's See", font=("Impact", 12, "italic"))
            if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
                answer2.config(text="Password could be better.")
            else:
                answer2.config(text="Password could be better.")
            answer3.config(
                text="Checking the internet to see if this Password has ever")
            answer4.config(text="been leaked before")
            semi_answer.config(text="Final Result:")
            final_answer.config(
                text=f"{password} has been found {count} times and shouldn't be used.")

        else:
            answer1.config(text="let's See", font=("Impact", 12, "italic"))
            if len(password) < 8 or not any(char.isdigit() for char in password) or not any(char.isupper() for char in password):
                answer2.config(text="Password could be better.")
            else:
                answer2.config(text="Password looks fine Generally.")
            answer3.config(
                text="Checking the internet to see if this Password has ever")
            answer4.config(text="been leaked before")
            semi_answer.config(text="Final Result:")
            final_answer.config(
                text=f"{password} wasn't found and its safe to use.")

    window.title("Secure Password")
    window.maxsize(width=510, height=600)
    window.config(bg=WHITE, padx=10, pady=10)

    canvas = Canvas(width=450, height=600, highlightthickness=0, bg=WHITE)
    logo = PhotoImage(file="logo.png")
    canvas.create_image(350, 100, image=logo)
    canvas.grid(row=1, column=1)

    entry_label = Label(text="Secure your password Fast!",
                        font=("Impact", 15, "italic"), bg=WHITE, fg=BLACK)
    entry_label.place(x=20, y=170)

    questtion_label = Label(text="What is the Password you currently have??", font=(
        "Impact", 15, "italic"), bg=WHITE, fg=BLACK)
    questtion_label.place(x=20, y=240)

    entry = Entry(width=30)
    entry.place(x=20, y=280)

    check_button = Button(text="Check Password", command=get_pass2)
    check_button.place(x=240, y=275)

    reset_button = Button(text="Reset", command=reset2)
    reset_button.place(x=350, y=275)

    answer1 = Label(text="", font=(
        "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
    answer1.place(x=20, y=330)

    answer2 = Label(text="", font=(
        "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
    answer2.place(x=20, y=350)

    answer3 = Label(text="", font=(
        "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
    answer3.place(x=20, y=370)

    answer4 = Label(text="", font=(
        "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
    answer4.place(x=20, y=390)

    semi_answer = Label(text="", font=(
        "Impact", 12, "italic"), bg=WHITE, fg=BLACK)
    semi_answer.place(x=20, y=440)

    final_answer = Label(text="", font=(
        "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
    final_answer.place(x=20, y=460)

    back_button = Button(text="Go Back", command=go_back)
    back_button.place(x=20, y=20)

    window.mainloop()


#----------------------------------User interface----------------------------------------#
# creating the window
window = Tk()
window.title("Secure Password")
window.maxsize(width=510, height=600)
window.config(bg=WHITE, padx=10, pady=10)

# creating the canvas
canvas = Canvas(width=450, height=600, highlightthickness=0, bg=WHITE)
logo = PhotoImage(file="logo.png")
canvas.create_image(350, 100, image=logo)
canvas.grid(row=1, column=1)

# the first label
entry_label = Label(text="Secure your password Fast!",
                    font=("Impact", 15, "italic"), bg=WHITE, fg=BLACK)
entry_label.place(x=20, y=170)

# the question label
questtion_label = Label(text="What is the Password you've been thinking about?", font=(
    "Impact", 15, "italic"), bg=WHITE, fg=BLACK)
questtion_label.place(x=20, y=240)

# the user input
entry = Entry(width=30)
entry.place(x=20, y=280)

# the check button
check_button = Button(text="Check Password", command=get_pass)
check_button.place(x=240, y=275)

# the reset button
reset_button = Button(text="Reset", command=reset)
reset_button.place(x=350, y=275)

# Check your current passowrd button
solo_chcek = Button(text="Check your current password", command=solo_chcecker)
solo_chcek.place(x=20, y=20)

# first stage checking answers label
answer1 = Label(text="", font=(
    "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
answer1.place(x=20, y=330)

answer2 = Label(text="", font=(
    "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
answer2.place(x=20, y=350)

answer3 = Label(text="", font=(
    "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
answer3.place(x=20, y=370)

answer4 = Label(text="", font=(
    "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
answer4.place(x=20, y=390)

# before the final result
semi_answer = Label(text="", font=(
    "Impact", 12, "italic"), bg=WHITE, fg=BLACK)
semi_answer.place(x=20, y=440)

# final stage checking label
final_answer = Label(text="", font=(
    "Impact", 12, "italic"), bg=WHITE, fg=ORANNGE)
final_answer.place(x=20, y=460)

window.mainloop()
