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


def td_format(td_object):
    # type: (datetime.timedelta) -> str
    # Formats the time left on a loan with its two largest units, like "2d 3h". Less than
    # a second, or a loan that has just run out, is "0s".
    seconds = int(td_object.total_seconds())
    periods = [
        ('y',        60*60*24*365),
        ('M',        60*60*24*30),
        ('d',        60*60*24),
        ('h',        60*60),
        ('m',        60),
        ('s',        1)
    ]

    strings=[]
    tick = 0
    for period_name, period_seconds in periods:
        # >= so that exactly one day is "1d", not "24h"
        if seconds >= period_seconds:
            period_value , seconds = divmod(seconds, period_seconds)
            strings.append("%s%s" % (period_value, period_name))
            tick += 1
        if tick >= 2:
            break

    if not strings:
        return "0s"

    return " ".join(strings)


def remove_overdue_books_from_list(loan_list):
    # Delete rented books that are overdue: 
    templist = []

    for book in loan_list:
        remaining = get_remaining_loan_time(book)

        if (remaining is None or remaining > datetime.timedelta(0)):
            # Book still valid, keep it on the list.
            templist.append(book)
        
    return templist


def is_loan_mine(book):
    # type: (dict) -> bool
    # Returns whether the loan record belongs to the account of the current activation.
    # Only the account that borrowed a book can return it, because the return request
    # is signed with that account's key. If the loan record has no user, or there's no
    # valid activation, this returns True, so the return is still attempted.

    from .libadobeAccount import getAccountUUID

    def bare_uuid(uuid):
        uuid = uuid.strip().lower()
        return uuid[len("urn:uuid:"):] if uuid.startswith("urn:uuid:") else uuid

    try:
        return bare_uuid(book["user"]) == bare_uuid(getAccountUUID())
    except (KeyError, TypeError, AttributeError):
        # No user in the loan record, or no account UUID
        return True
