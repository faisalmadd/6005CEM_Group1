console.log('hello world quiz')
const quizBox = document.getElementById('quiz-box')     // insert questions and answers to line 101 of quiz_form.html
const url = window.location.href
let quiz_data



$.ajax({
    type: 'GET',
    url: `${url}data`,        // get dictionary created from JsonResponse in quiz_data_view in views.py
    success: function(response){
        console.log(response)
        data = response.quiz_data    // get every element of quiz and answers from dictionary
        data.forEach(el => {        // to loop each question from the dictionary to take quiz page
            for (const [question, answers] of Object.entries(el)){
                quizBox.innerHTML += `
                    <br>
                    <div class="mb-2">
                        <b>${question}</b>
                    </div>
                `

                answers.forEach(answer => {     // to loop each answer from the dictionary to take quiz page
                    quizBox.innerHTML += `
                        <div>
                            <input type="radio" class="ans" id="${question}-${answer}" name="${question}" value="${answer}">
                            <label for="${question}">${answer}</label>
                        </div>
                        <hr>
                    `
                })
            }
        });
    },
    error: function(error){
        console.log(error)
    }
})

const quizForm =  document.getElementById('quiz-form')
const csrf = document.getElementsByName('csrfmiddlewaretoken')

const sendData = () => {
    const elements = [...document.getElementsByClassName('ans')]
    const data = {}
    data['csrfmiddlewaretoken'] = csrf[0].value
    elements.forEach(el=>{
        if (el.checked) {
            data[el.name] = el.value
        } else {
            if (!data[el.name]) {
                data[el.name] = null
            }
        }
    })

    $.ajax({
        type: 'POST',
        url: `${url}save/`,
        data: data,
        success: function(response){
            // console.log(response)
            const results = response.results
            console.log(results)
            quizForm.classList.add('not-visible')

            results.forEach(res=>{
                const resDiv = document.createElement("div")
                for (const [question, resp] of Object.entries(res)){
                    console.log(question)
                    console.log(resp)
                    console.log('*****')

                    resDiv.innerHTML += question
                    const cls = ['container', 'p-3', 'text-light', 'h3']
                    resDiv.classList.add(...cls)

                    if (resp=='not answered') {
                        resDiv.innerHTML += '- not answered'
                        resDiv.classList.add('bg-danger')
                    }

                    else {
                        const answer = resp['answered']
                        const correct = resp['correct_answer']

                        console.log(answer,correct)
                        if (answer == correct) {
                            resDiv.classList.add('bg-success')
                            resDiv.innerHTML += `answered: ${answer}`
                        } else {
                            resDiv.classList.add('bg-danger')
                            resDiv.innerHTML += ` | correct answer: ${correct}`
                            resDiv.innerHTML += ` | answered: ${answer}`
                        }
                    }
                }
                const body = document.getElementsByTagName('MAIN')[0]
                body.append(resDiv)
            })
        },
        error: function(error){
            console.log(error)
        }

    })

}

quizForm.addEventListener('submit', e=>{
    e.preventDefault()

    sendData()
})