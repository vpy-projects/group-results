
## About hdfstop.py

### How to execute this program

    $ python hdfstop.py --audit_log hdfs-audit.log --group_by ugi,cmd --limit 10

### To quickly time the program

    $ time python hdfstop.py --audit_log hdfs-audit.log --group_by ugi,cmd --limit 10

### few other parameters which might be useful to group the results

    #### to get the list of results for a specific client node(ip address)

    $ python hdfstop.py --audit_log hdfs-audit.log --group_by ugi,cmd,ip --limit 10

    #### to get the list of results for a specific time range (date)

    $ python hdfstop.py --audit_log hdfs-audit.log --group_by ugi,cmd,date --limit 10


### To execute unit tests

    $ python test-hdfstop.py --verbose


#### Auto-remediation

    Extracting results based on grouping of fields is ideally effective
    to achieve by using a Structured Query Language.

    Can forward such audit logs to a Logging framework like Splunk or Logstash etc.

    Can query the results with grouping and filtering very easily by writing
    Splunk queries

    Performance of these queries is much faster by using such frameworks or systems.

    Can create alerts from these queries as part of proactive monitoring
    and there by reduce incidents or outages.

#### General Comments

    Would have extended the tool on logging.
    Can try to do parallel or multiple processing so as to improve the performance.
