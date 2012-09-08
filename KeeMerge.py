from lxml import etree
import datetime, glob

class Password(object):
    def __init__(self, node):
        date= node.find("lastmodtime").text
        self.lastmodtime= datetime.datetime.strptime(date,"%Y-%m-%dT%H:%M:%S")
        self.uuid= node.find("uuid").text
        self.username= node.find("username").text
        self.password= node.find("password").text
        self.title= node.find("title").text
        self.node= node

    def __hash__(self):
        return hash(str(self.title)+str(self.lastmodtime)+str(self.uuid))

    def __eq__(self,other):
        return self.uuid==other.uuid and self.username==other.username and self.password==other.password and self.title==self.title


    def __str__(self):

        s = "%s (%s): [%s|%s] - %s" % (self.title,self.uuid,self.username,self.password,self.lastmodtime)
        return s

    def __repr__(self):

        s = "%s (%s): [%s|%s] - %s" % (self.title,self.uuid,self.username,self.password,self.lastmodtime)
        return s


def getTree(file):
    """
    Give the root and tree of the XML file
    """
    parser = etree.XMLParser(strip_cdata=False)
    tree = etree.parse(file, parser)
    root= tree.getroot()
    return tree ,root

def getpasswords(file):
    """
    Parse and return all the password of an xml exported by Keepass
    """
    tree, root = getTree(file)
    elements= []
    for e in root:
        elements.append(Password(e))
    return elements

def main():
    # give me your xmls
    xmls= glob.glob("*.xml")

    # a dict uniq by the uuid of the node
    uniquepasswords= dict()

    # all your passwords are belong to us
    passwords=[pwd for f in xmls for pwd in getpasswords(f)]

    # let's go marco
    for pwd in passwords:
        # do I know you ?
        if pwd.uuid in uniquepasswords:
            challenger= pwd
            champion= uniquepasswords[pwd.uuid]
            # If exact match, skips
            if challenger != champion:
                # challenger modified recently ?
                if challenger.lastmodtime > champion.lastmodtime:
                    print "####"
                    print "%s" % (challenger)
                    print "more recent than"
                    print "%s" % (champion)
                    print "Challenger wins"
                    uniquepasswords[pwd.uuid]= challenger
                elif challenger.lastmodtime < champion.lastmodtime:
                    print "####"
                    print "%s" % (challenger)
                    print "older than"
                    print "%s" % (champion)
                    print "Garbage"
        else:
            # hello you
            uniquepasswords[pwd.uuid]= pwd

    # Append xml nodes to root
    root= etree.Element("pwlist")
    for pwd in uniquepasswords.values():
        root.append(pwd.node)

    # Write to file
    et = etree.ElementTree(root)
    et.write("merge.xml", pretty_print=True, xml_declaration=True, encoding='utf-8', standalone='yes')

if __name__ == "__main__":
    main()
