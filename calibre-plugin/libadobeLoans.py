import sys, datetime

def remove_overdue_books_from_list(loan_list):
	# Delete rented books that are overdue: 
	templist = []

	for book in loan_list:
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
			timestamp = 0
			continue

		if (currenttime < timestamp or timestamp == 0):
			# Book still valid, keep it on the list.
			templist.append(book)
		
	return templist
