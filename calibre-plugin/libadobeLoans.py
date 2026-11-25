import sys, datetime

def get_remaining_loan_time(book):
    # type: (dict) -> datetime.timedelta
    # Returns how much time is left on the loan (negative once it's over), or None
    # if the loan record has no valid validUntil timestamp.

    # This implementation behaves differently on Python < 3.7 and on >= 3.7. 
    # Older Python versions only support UTC timestamps, newer versions also
    # accept a timezone. This shouldn't be a problem in our case since I've
    # never seen a loan whose validity timestamp had a timezone.

    try:
        book_time_stamp = book["validUntil"]
        if sys.version_info < (3, 7, 0):
            # https://blog.miguelgrinberg.com/post/it-s-time-for-a-change-datetime-utcnow-is-now-deprecated
            timestamp = datetime.datetime.strptime(book_time_stamp, "%Y-%m-%dT%H:%M:%SZ")
            currenttime = datetime.datetime.utcnow()
        else:
            timestamp = datetime.datetime.strptime(book_time_stamp, "%Y-%m-%dT%H:%M:%S%z")
            currenttime = datetime.datetime.now(datetime.timezone.utc)

    except:
        # Invalid book timestamp
        return None

    return timestamp - currenttime


def remove_overdue_books_from_list(loan_list):
    # Delete rented books that are overdue: 
    templist = []

    for book in loan_list:
        remaining = get_remaining_loan_time(book)

        if (remaining is None or remaining > datetime.timedelta(0)):
            # Book still valid, keep it on the list.
            templist.append(book)
        
    return templist
