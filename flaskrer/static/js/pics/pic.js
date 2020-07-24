function get_comments_id(id) {
    function get_comments() {
        $.getJSON(
            `/api/comment/${id}`,
            null,
            function(response) {
                let comments = $('#comments')
                comments.empty()

                response.forEach(function(comment) {
                    let div_comment = document.createElement('div')
                    div_comment.classList.add('comment')

                    comments.append(document.createElement('hr'))

                    let div_username = document.createElement('div')
                    div_username.classList.add('comment-username')
                    let text_username = document.createTextNode(`@${comment.username}`)
                    div_username.appendChild(text_username)

                    let div_created = document.createElement('div')
                    div_created.classList.add('comment-created')
                    let text_created = document.createTextNode(`Posted on ${comment.created}`)
                    div_created.appendChild(text_created)

                    let div_content = document.createElement('div')
                    div_content.classList.add('comment-content')
                    let text_content = document.createTextNode(comment.content)
                    div_content.appendChild(text_content)

                    div_comment.appendChild(div_username)
                    div_comment.appendChild(div_created)
                    div_comment.appendChild(div_content)

                    comments.append(div_comment)
                })
            }
        )
    }

    return get_comments
}


function main() {
    let segments = window.location.pathname.split('/')
    let post_id = segments.pop() | segments.pop()
    let get_this_comments = get_comments_id(post_id)

    get_this_comments()

    $('#submit_comment_button').click(function() {
        let comment = $('#input_comment').val()

        if (comment.length == 0) {
            alert('Empty comment')
            return
        }

        let data = {'content': comment}

        $.ajax({
            url: `/api/comment/${post_id}`,
            type: 'POST',
            dataType: 'json',
            contentType: 'application/json',
            success: get_this_comments,
            error: function() {
                alert("Couldn't post comment")
            },
            data: JSON.stringify(data)
        });

    })
}

main()
